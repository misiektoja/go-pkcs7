package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ErrAttributeNotFound is returned when a requested signed attribute is absent.
var ErrAttributeNotFound = errors.New("pkcs7: attribute type not in attributes")

// VerifyOptions controls the checks Verify makes.
type VerifyOptions struct {
	// Roots holds the trust anchors for signer certificate chains. When nil, Verify checks the
	// signatures but builds no chain, so the caller must decide whether to trust the signer.
	Roots *x509.CertPool

	// Intermediates holds certificates that may complete a signer chain, in addition to the
	// certificates carried in the message.
	Intermediates []*x509.Certificate

	// SignerCertificates holds candidate signer certificates for messages that do not carry their
	// signer certificate. Some SCEP servers send responses without one.
	SignerCertificates []*x509.Certificate

	// CurrentTime is the time at which chains are checked. When zero, the current time is used,
	// unless VerifyAtSigningTime applies.
	CurrentTime time.Time

	// VerifyAtSigningTime checks chains at the time in the signing-time attribute when CurrentTime
	// is zero. The signer chooses that time, so set it only for archived signatures whose signing
	// time is trusted.
	VerifyAtSigningTime bool

	// KeyUsages lists the extended key usages a signer chain must allow. When empty, any usage is
	// accepted.
	KeyUsages []x509.ExtKeyUsage

	// AllowMD5 accepts signers that use the MD5 digest. Some old SCEP clients still do.
	AllowMD5 bool
}

// Verify checks every signer of a SignedData message: the message digest, the signed attributes,
// the signature and, when opts.Roots is set, the signer certificate chain. For a detached
// signature, set p7.Content to the signed data first.
func (p7 *PKCS7) Verify(opts VerifyOptions) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySigner(p7, sd.ContentInfo.ContentType, signer, opts); err != nil {
			return err
		}
	}
	return nil
}

// SigningTimeNotValidError is returned when the signing time attribute
// falls outside of the signer certificate validity.
type SigningTimeNotValidError struct {
	SigningTime time.Time
	NotBefore   time.Time // NotBefore of signer
	NotAfter    time.Time // NotAfter of signer
}

// Error implements error.
func (e *SigningTimeNotValidError) Error() string {
	return fmt.Sprintf("pkcs7: signing time %q is outside of certificate validity %q to %q",
		e.SigningTime.Format(time.RFC3339),
		e.NotBefore.Format(time.RFC3339),
		e.NotAfter.Format(time.RFC3339))
}

// verifySigner checks one signer of a SignedData message.
func verifySigner(p7 *PKCS7, contentType asn1.ObjectIdentifier, signer signerInfo, opts VerifyOptions) error {
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if ee == nil {
		ee = getCertFromCertsByIssuerAndSerial(opts.SignerCertificates, signer.IssuerAndSerialNumber)
	}
	if ee == nil {
		return errors.New("pkcs7: no certificate for signer")
	}
	hash, err := signerDigestHash(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	if hash == crypto.MD5 && !opts.AllowMD5 {
		return errors.New("pkcs7: signer uses the MD5 digest, which is not allowed")
	}

	signed := p7.Content
	var signingTime time.Time
	if len(signer.AuthenticatedAttributes) > 0 {
		if err := checkContentTypeAttribute(signer.AuthenticatedAttributes, contentType); err != nil {
			return err
		}
		var digest []byte
		if err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeMessageDigest, &digest); err != nil {
			return fmt.Errorf("pkcs7: message-digest attribute: %w", err)
		}
		computed, err := calculateHash(p7.Hasher, hash, p7.Content)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(digest, computed) != 1 {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}
		signed, err = encodeSignedAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
		switch err := unmarshalAttribute(signer.AuthenticatedAttributes, OIDAttributeSigningTime, &signingTime); {
		case errors.Is(err, ErrAttributeNotFound):
		case err != nil:
			return fmt.Errorf("pkcs7: signing-time attribute: %w", err)
		case signingTime.After(ee.NotAfter) || signingTime.Before(ee.NotBefore):
			return &SigningTimeNotValidError{
				SigningTime: signingTime,
				NotBefore:   ee.NotBefore,
				NotAfter:    ee.NotAfter,
			}
		}
	}

	if err := checkSignature(ee.PublicKey, signer, hash, signed); err != nil {
		return err
	}
	if opts.Roots == nil {
		return nil
	}
	currentTime := opts.CurrentTime
	if currentTime.IsZero() && opts.VerifyAtSigningTime {
		currentTime = signingTime
	}
	intermediates := slices.Concat(p7.Certificates, opts.Intermediates)
	_, err = verifyCertChain(ee, intermediates, opts.Roots, currentTime, opts.KeyUsages)
	return err
}

// signerDigestHash returns the hash a signer digest algorithm names. Some signers, such as the
// Azure instance metadata attestation service, put a PKCS #1 v1.5 signature algorithm there.
func signerDigestHash(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	for hash, signatureOID := range rsaSignatureAlgorithms {
		if oid.Equal(signatureOID) {
			return hash, nil
		}
	}
	return getHashForOID(oid)
}

// checkContentTypeAttribute enforces RFC 5652 section 5.3: signed attributes carry exactly one
// content-type attribute, equal to the encapsulated content type.
func checkContentTypeAttribute(attrs []attribute, contentType asn1.ObjectIdentifier) error {
	var signedType asn1.ObjectIdentifier
	if err := unmarshalAttribute(attrs, OIDAttributeContentType, &signedType); err != nil {
		return fmt.Errorf("pkcs7: content-type attribute: %w", err)
	}
	if !signedType.Equal(contentType) {
		return fmt.Errorf("pkcs7: content-type attribute %v does not match the content type %v", signedType, contentType)
	}
	return nil
}

// checkSignature verifies a signer's signature over signed with the signer public key.
func checkSignature(pub crypto.PublicKey, signer signerInfo, hash crypto.Hash, signed []byte) error {
	h := hash.New()
	h.Write(signed)
	digest := h.Sum(nil)
	alg := signer.DigestEncryptionAlgorithm.Algorithm
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		switch {
		case alg.Equal(OIDEncryptionAlgorithmRSASSAPSS):
			saltLength, err := pssSaltLength(signer.DigestEncryptionAlgorithm.Parameters, hash)
			if err != nil {
				return err
			}
			pssOpts := &rsa.PSSOptions{SaltLength: saltLength, Hash: hash}
			if err := rsa.VerifyPSS(pub, hash, digest, signer.EncryptedDigest, pssOpts); err != nil {
				return fmt.Errorf("pkcs7: signature verification failed: %w", err)
			}
			return nil
		case alg.Equal(OIDEncryptionAlgorithmRSA) || alg.Equal(rsaSignatureAlgorithms[hash]):
			if err := rsa.VerifyPKCS1v15(pub, hash, digest, signer.EncryptedDigest); err != nil {
				return fmt.Errorf("pkcs7: signature verification failed: %w", err)
			}
			return nil
		}
	case *ecdsa.PublicKey:
		// Some signers name the curve instead of the ECDSA signature algorithm.
		if alg.Equal(ecdsaSignatureAlgorithms[hash]) || alg.Equal(OIDEncryptionAlgorithmECDSAP256) ||
			alg.Equal(OIDEncryptionAlgorithmECDSAP384) || alg.Equal(OIDEncryptionAlgorithmECDSAP521) {
			if !ecdsa.VerifyASN1(pub, digest, signer.EncryptedDigest) {
				return errors.New("pkcs7: signature verification failed: ECDSA verification failure")
			}
			return nil
		}
	default:
		return fmt.Errorf("pkcs7: unsupported signer key type %T", pub)
	}
	return fmt.Errorf("pkcs7: signature algorithm %v cannot be used with digest %v and key type %T", alg, hash, pub)
}

// pssParameters is RSASSA-PSS-params from RFC 4055 section 3.1.
type pssParameters struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength   int                      `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// pssSaltLength decodes RSASSA-PSS parameters and returns the salt length. The parameter hash and
// the MGF1 hash must both equal the signer digest, because crypto/rsa uses one hash for both.
func pssSaltLength(params asn1.RawValue, hash crypto.Hash) (int, error) {
	if len(params.FullBytes) == 0 {
		return 0, errors.New("pkcs7: RSASSA-PSS signature without parameters")
	}
	var p pssParameters
	rest, err := asn1.Unmarshal(params.FullBytes, &p)
	if err != nil {
		return 0, fmt.Errorf("pkcs7: malformed RSASSA-PSS parameters: %w", err)
	}
	if len(rest) > 0 {
		return 0, errors.New("pkcs7: trailing data after RSASSA-PSS parameters")
	}
	paramHash, mgfHash, err := parseHashAndMGF(p.Hash, p.MGF)
	if err != nil {
		return 0, err
	}
	if paramHash != hash || mgfHash != hash {
		return 0, fmt.Errorf("pkcs7: RSASSA-PSS hashes %v and %v do not match the digest %v", paramHash, mgfHash, hash)
	}
	if p.TrailerField != 1 || p.SaltLength < 0 {
		return 0, errors.New("pkcs7: unsupported RSASSA-PSS parameters")
	}
	return p.SaltLength, nil
}

// parseHashAndMGF decodes the hash and MGF1 hash of RSASSA-PSS or RSAES-OAEP parameters. Absent
// fields take the SHA-1 defaults from RFC 8017.
func parseHashAndMGF(hashAlg, mgfAlg pkix.AlgorithmIdentifier) (crypto.Hash, crypto.Hash, error) {
	hash := crypto.SHA1
	if len(hashAlg.Algorithm) > 0 {
		var err error
		if hash, err = getHashForOID(hashAlg.Algorithm); err != nil || hash == crypto.MD5 {
			return 0, 0, fmt.Errorf("pkcs7: unsupported RSA parameter hash %v", hashAlg.Algorithm)
		}
	}
	mgfHash := crypto.SHA1
	if len(mgfAlg.Algorithm) > 0 {
		if !mgfAlg.Algorithm.Equal(OIDMaskGenerationFunctionMGF1) {
			return 0, 0, fmt.Errorf("pkcs7: unsupported mask generation function %v", mgfAlg.Algorithm)
		}
		var mgfHashAlg pkix.AlgorithmIdentifier
		rest, err := asn1.Unmarshal(mgfAlg.Parameters.FullBytes, &mgfHashAlg)
		if err != nil || len(rest) > 0 {
			return 0, 0, errors.New("pkcs7: malformed MGF1 parameters")
		}
		if mgfHash, err = getHashForOID(mgfHashAlg.Algorithm); err != nil || mgfHash == crypto.MD5 {
			return 0, 0, fmt.Errorf("pkcs7: unsupported MGF1 hash %v", mgfHashAlg.Algorithm)
		}
	}
	return hash, mgfHash, nil
}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (p7 *PKCS7) GetOnlySigner() *x509.Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

// UnmarshalSignedAttribute decodes a signed attribute of the first signer into out. The attribute
// must appear once with a single value. It returns ErrAttributeNotFound when it is absent.
func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out any) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

// parseSignedData decodes the content of a SignedData ContentInfo.
func parseSignedData(data []byte, opts ParseOptions) (*PKCS7, error) {
	var sd signedData
	rest, err := asn1.Unmarshal(data, &sd)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data after SignedData"}
	}
	certs, err := sd.Certificates.Parse(opts.LegacyCertificateParser)
	if err != nil {
		return nil, err
	}

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	// Compound octet string
	if compound.IsCompound {
		if compound.Tag == asn1.TagOctetString {
			if content, err = joinOctetStrings(compound.Bytes); err != nil {
				return nil, err
			}
		} else {
			content = compound.Bytes
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

// joinOctetStrings concatenates the primitive OCTET STRING segments of a constructed OCTET STRING.
func joinOctetStrings(segments []byte) ([]byte, error) {
	var out []byte
	for len(segments) > 0 {
		var segment asn1.RawValue
		rest, err := asn1.Unmarshal(segments, &segment)
		if err != nil {
			return nil, err
		}
		if segment.Class != asn1.ClassUniversal || segment.Tag != asn1.TagOctetString || segment.IsCompound {
			return nil, errors.New("pkcs7: constructed OCTET STRING holds an element that is not a primitive OCTET STRING")
		}
		out = append(out, segment.Bytes...)
		segments = rest
	}
	return out, nil
}

// verifyCertChain builds a chain from ee to one of the roots, using certs as intermediates. A zero
// currentTime means the current time. Empty keyUsages accept any extended key usage.
func verifyCertChain(ee *x509.Certificate, certs []*x509.Certificate, roots *x509.CertPool, currentTime time.Time, keyUsages []x509.ExtKeyUsage) ([][]*x509.Certificate, error) {
	intermediates := x509.NewCertPool()
	for _, intermediate := range certs {
		intermediates.AddCert(intermediate)
	}
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	chains, err := ee.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     keyUsages,
		CurrentTime:   currentTime,
	})
	if err != nil {
		return chains, fmt.Errorf("pkcs7: failed to verify certificate chain: %w", err)
	}
	return chains, nil
}

// MessageDigestMismatchError is returned when the signer data digest does not
// match the computed digest for the contained content
type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

// Error implements error.
func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X",
		err.ExpectedDigest, err.ActualDigest)
}

// getCertFromCertsByIssuerAndSerial returns the certificate with the issuer and serial number, or nil.
func getCertFromCertsByIssuerAndSerial(certs []*x509.Certificate, ias issuerAndSerial) *x509.Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

// unmarshalAttribute decodes the single value of an attribute that must appear once in attrs.
func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out any) error {
	var found *attribute
	for i := range attrs {
		if !attrs[i].Type.Equal(attributeType) {
			continue
		}
		if found != nil {
			return fmt.Errorf("pkcs7: attribute %v appears more than once", attributeType)
		}
		found = &attrs[i]
	}
	if found == nil {
		return ErrAttributeNotFound
	}
	if found.Value.Class != asn1.ClassUniversal || found.Value.Tag != asn1.TagSet {
		return fmt.Errorf("pkcs7: attribute %v values are not a SET", attributeType)
	}
	rest, err := asn1.Unmarshal(found.Value.Bytes, out)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("pkcs7: attribute %v has more than one value", attributeType)
	}
	return nil
}

// calculateHash hashes content with the custom hasher when one is set.
func calculateHash(hasher Hasher, hashFunc crypto.Hash, content []byte) (computed []byte, err error) {
	if hasher != nil {
		return hasher.Hash(hashFunc, bytes.NewReader(content))
	}
	if !hashFunc.Available() {
		return nil, fmt.Errorf("hash function %v not available", hashFunc)
	}
	h := hashFunc.New()
	_, _ = h.Write(content)
	return h.Sum(nil), nil
}
