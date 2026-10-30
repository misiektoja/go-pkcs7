package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd                  signedData
	certs               []*x509.Certificate
	data, messageDigest []byte
	digestOid           asn1.ObjectIdentifier
	encryptionOid       asn1.ObjectIdentifier
}

// NewSignedData starts a SignedData message over data. Signers use SHA-256 unless
// SetDigestAlgorithm is called before they are added.
func NewSignedData(data []byte) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	ci := contentInfo{
		ContentType: OIDData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	sd := signedData{
		ContentInfo: ci,
		Version:     1,
	}
	return &SignedData{sd: sd, data: data, digestOid: OIDDigestAlgorithmSHA256}, nil
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
	ExtraSignedAttributes   []Attribute
	ExtraUnsignedAttributes []Attribute

	// SigningTime is the value of the signing-time attribute. When zero, the current time is used.
	SigningTime time.Time
}

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,omitempty,tag:1"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// encodeSignedAttributes returns the DER SET OF that a signature over signed attributes covers
// (RFC 5652 section 5.4). It keeps the order of attrs, so a parsed message is checked against the
// bytes its signer encoded even when that signer did not sort the set.
func encodeSignedAttributes(attrs []attribute) ([]byte, error) {
	var content []byte
	for _, attr := range attrs {
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		content = append(content, encoded...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: content})
}

type rawCertificates struct {
	Raw asn1.RawContent
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// SetDigestAlgorithm sets the digest algorithm, such as OIDDigestAlgorithmSHA256, for signers added
// afterwards.
func (sd *SignedData) SetDigestAlgorithm(d asn1.ObjectIdentifier) {
	sd.digestOid = d
}

// SetEncryptionAlgorithm sets the signature algorithm identifier for signers added afterwards. It
// must suit the signer key and digest. For RSA keys, OIDEncryptionAlgorithmRSA is accepted with any
// digest. When unset, the identifier is derived from the key and digest.
func (sd *SignedData) SetEncryptionAlgorithm(d asn1.ObjectIdentifier) {
	sd.encryptionOid = d
}

// signatureAlgorithm returns the signature algorithm identifier for a signer key and digest.
func (sd *SignedData) signatureAlgorithm(pub crypto.PublicKey, hash crypto.Hash) (asn1.ObjectIdentifier, error) {
	derived, err := getOIDForEncryptionAlgorithm(pub, hash)
	if err != nil {
		return nil, err
	}
	if sd.encryptionOid == nil || sd.encryptionOid.Equal(derived) {
		return derived, nil
	}
	if _, isRSA := pub.(*rsa.PublicKey); isRSA && sd.encryptionOid.Equal(OIDEncryptionAlgorithmRSA) {
		return OIDEncryptionAlgorithmRSA, nil
	}
	return nil, fmt.Errorf("pkcs7: signature algorithm %v cannot be used with digest %v and key type %T",
		sd.encryptionOid, hash, pub)
}

// addDigestAlgorithm records the digest algorithm in the SignedData digestAlgorithms set once.
func (sd *SignedData) addDigestAlgorithm() {
	for _, alg := range sd.sd.DigestAlgorithmIdentifiers {
		if alg.Algorithm.Equal(sd.digestOid) {
			return
		}
	}
	sd.sd.DigestAlgorithmIdentifiers = append(sd.sd.DigestAlgorithmIdentifiers,
		pkix.AlgorithmIdentifier{Algorithm: sd.digestOid})
}

// AddSigner is a wrapper around AddSignerChain() that adds a signer without any parent.
func (sd *SignedData) AddSigner(ee *x509.Certificate, key crypto.Signer, config SignerInfoConfig) error {
	return sd.AddSignerChain(ee, key, nil, config)
}

// AddSignerChain signs attributes about the content and adds certificates and signer infos to the
// SignedData. The end-entity certificate and key issue the signature. Parents that should travel
// with the message are listed in order, the issuer of ee first.
//
// The signed attributes are content-type, message-digest and signing-time, followed by
// config.ExtraSignedAttributes.
func (sd *SignedData) AddSignerChain(ee *x509.Certificate, key crypto.Signer, parents []*x509.Certificate, config SignerInfoConfig) error {
	// Following RFC 2315, 9.2 SignerInfo type, the distinguished name of
	// the issuer of the end-entity signer is stored in the issuerAndSerialNumber
	// section of the SignedData.SignerInfo, alongside the serial number of
	// the end-entity.
	var ias issuerAndSerial
	ias.SerialNumber = ee.SerialNumber
	if len(parents) == 0 {
		// no parent, the issuer is the end-entity cert itself
		ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
	} else {
		err := verifyPartialChain(ee, parents)
		if err != nil {
			return err
		}
		// the first parent is the issuer
		ias.IssuerName = asn1.RawValue{FullBytes: parents[0].RawSubject}
	}
	hash, err := getHashForOID(sd.digestOid)
	if err != nil {
		return err
	}
	encryptionOid, err := sd.signatureAlgorithm(key.Public(), hash)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(sd.data)
	sd.messageDigest = h.Sum(nil)
	signingTime := config.SigningTime
	if signingTime.IsZero() {
		signingTime = time.Now()
	}
	attrs := &attributes{}
	attrs.Add(OIDAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(OIDAttributeMessageDigest, sd.messageDigest)
	attrs.Add(OIDAttributeSigningTime, signingTime.UTC())
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshalling()
	if err != nil {
		return err
	}
	unsignedAttrs := &attributes{}
	for _, attr := range config.ExtraUnsignedAttributes {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}
	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}
	// create signature of signed attributes
	signature, err := signAttributes(finalAttrs, key, hash)
	if err != nil {
		return err
	}
	signer := signerInfo{
		AuthenticatedAttributes:   finalAttrs,
		UnauthenticatedAttributes: finalUnsignedAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: encryptionOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	sd.addDigestAlgorithm()
	sd.certs = append(sd.certs, ee)
	if len(parents) > 0 {
		sd.certs = append(sd.certs, parents...)
	}
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)
	return nil
}

// SignWithoutAttr issues a signature on the content of the pkcs7 SignedData.
// Unlike AddSigner/AddSignerChain, it calculates the digest on the data alone
// and does not include any signed attributes like timestamp and so on.
//
// This function is needed to sign old Android APKs, something you probably
// shouldn't do unless you're maintaining backward compatibility for old
// applications.
func (sd *SignedData) SignWithoutAttr(ee *x509.Certificate, key crypto.Signer, _ SignerInfoConfig) error {
	hash, err := getHashForOID(sd.digestOid)
	if err != nil {
		return err
	}
	encryptionOid, err := sd.signatureAlgorithm(key.Public(), hash)
	if err != nil {
		return err
	}
	h := hash.New()
	h.Write(sd.data)
	sd.messageDigest = h.Sum(nil)
	signature, err := key.Sign(rand.Reader, sd.messageDigest, hash)
	if err != nil {
		return err
	}
	var ias issuerAndSerial
	ias.SerialNumber = ee.SerialNumber
	// no parent, the issue is the end-entity cert itself
	ias.IssuerName = asn1.RawValue{FullBytes: ee.RawIssuer}
	signer := signerInfo{
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: sd.digestOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: encryptionOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	sd.addDigestAlgorithm()
	sd.certs = append(sd.certs, ee)
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)
	return nil
}

// SetUnauthenticatedAttributes replaces the unsigned attributes of a signer.
func (si *signerInfo) SetUnauthenticatedAttributes(extraUnsignedAttrs []Attribute) error {
	unsignedAttrs := &attributes{}
	for _, attr := range extraUnsignedAttrs {
		unsignedAttrs.Add(attr.Type, attr.Value)
	}
	finalUnsignedAttrs, err := unsignedAttrs.ForMarshalling()
	if err != nil {
		return err
	}

	si.UnauthenticatedAttributes = finalUnsignedAttrs

	return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (sd *SignedData) AddCertificate(cert *x509.Certificate) {
	sd.certs = append(sd.certs, cert)
}

// RemoveCertificates leaves every certificate out of the message, including the signer
// certificates. RFC 5652 allows this when recipients already hold the signer certificate, as SCEP
// clients do from GetCACert.
func (sd *SignedData) RemoveCertificates() {
	sd.certs = nil
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() {
	sd.sd.ContentInfo = contentInfo{ContentType: OIDData}
}

// GetSignedData returns the private Signed Data
func (sd *SignedData) GetSignedData() *signedData {
	return &sd.sd
}

// Finish marshals the content and its signers
func (sd *SignedData) Finish() ([]byte, error) {
	certs, err := marshalCertificates(sd.certs)
	if err != nil {
		return nil, err
	}
	sd.sd.Certificates = certs
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

// RemoveAuthenticatedAttributes removes authenticated attributes from signedData
// similar to OpenSSL's PKCS7_NOATTR or -noattr flags
func (sd *SignedData) RemoveAuthenticatedAttributes() {
	for i := range sd.sd.SignerInfos {
		sd.sd.SignerInfos[i].AuthenticatedAttributes = nil
	}
}

// RemoveUnauthenticatedAttributes removes unauthenticated attributes from signedData
func (sd *SignedData) RemoveUnauthenticatedAttributes() {
	for i := range sd.sd.SignerInfos {
		sd.sd.SignerInfos[i].UnauthenticatedAttributes = nil
	}
}

// verifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func verifyPartialChain(cert *x509.Certificate, parents []*x509.Certificate) error {
	if len(parents) == 0 {
		return fmt.Errorf("pkcs7: zero parents provided to verify the signature of certificate %q", cert.Subject.CommonName)
	}
	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		return fmt.Errorf("pkcs7: certificate signature from parent is invalid: %w", err)
	}
	if len(parents) == 1 {
		// there is no more parent to check, return
		return nil
	}
	return verifyPartialChain(parents[0], parents[1:])
}

// cert2issuerAndSerial returns the issuer and serial number that identify cert.
func cert2issuerAndSerial(cert *x509.Certificate) issuerAndSerial {
	// The issuer RDNSequence has to match exactly the sequence in the certificate
	// We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
	return issuerAndSerial{
		IssuerName:   asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	}
}

// signAttributes signs the DER encoding of the signed attributes.
func signAttributes(attrs []attribute, key crypto.Signer, digestAlg crypto.Hash) ([]byte, error) {
	attrBytes, err := encodeSignedAttributes(attrs)
	if err != nil {
		return nil, err
	}
	h := digestAlg.New()
	h.Write(attrBytes)
	return key.Sign(rand.Reader, h.Sum(nil), digestAlg)
}

// marshalCertificates concatenates the certificates into a SignedData certificate set.
func marshalCertificates(certs []*x509.Certificate) (rawCertificates, error) {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	return marshalCertificateBytes(buf.Bytes())
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (rawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return rawCertificates{}, err
	}
	return rawCertificates{Raw: b}, nil
}

// DegenerateCertificate creates a signed data structure containing only the
// provided certificate or certificate chain.
func DegenerateCertificate(cert []byte) ([]byte, error) {
	rawCert, err := marshalCertificateBytes(cert)
	if err != nil {
		return nil, err
	}
	return marshalDegenerate(signedData{
		Version:      1,
		ContentInfo:  contentInfo{ContentType: OIDData},
		Certificates: rawCert,
		CRLs:         []pkix.CertificateList{},
	})
}

// DegenerateCRL creates a signed data structure with no signers and no certificates that carries
// one DER encoded CRL, the form of a SCEP GetCRL response (RFC 8894).
func DegenerateCRL(crl []byte) ([]byte, error) {
	var list pkix.CertificateList
	rest, err := asn1.Unmarshal(crl, &list)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: malformed CRL: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pkcs7: trailing data after the CRL")
	}
	return marshalDegenerate(signedData{
		Version:     1,
		ContentInfo: contentInfo{ContentType: OIDData},
		CRLs:        []pkix.CertificateList{list},
	})
}

// marshalDegenerate wraps a signed data structure without signers in a content info.
func marshalDegenerate(sd signedData) ([]byte, error) {
	content, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	signedContent := contentInfo{
		ContentType: OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	return asn1.Marshal(signedContent)
}
