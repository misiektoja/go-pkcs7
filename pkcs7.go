// Package pkcs7 parses and builds the parts of the Cryptographic Message Syntax (CMS, RFC 5652)
// that certificate enrollment protocols such as SCEP use: SignedData, EnvelopedData with RSA key
// transport and EncryptedData with a pre-shared key.
//
// Algorithm choices are made per call through option structs. Nothing is configured through
// package variables.
package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"sort"

	_ "crypto/md5"  // registers crypto.MD5 for legacy SCEP signers
	_ "crypto/sha1" // registers crypto.SHA1
	_ "crypto/sha256"
	_ "crypto/sha512"

	legacyx509 "github.com/misiektoja/go-pkcs7/internal/legacy/x509"
)

// PKCS7 is a parsed CMS message.
type PKCS7 struct {
	Content      []byte
	Certificates []*x509.Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	Hasher       Hasher
	raw          any
}

// Hasher is an interface defining a custom hash calculator.
type Hasher interface {
	Hash(crypto.Hash, io.Reader) ([]byte, error)
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content type is not supported.
// Only SignedData, EnvelopedData and EncryptedData are supported.
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

type unsignedData []byte

var (
	// Signed Data OIDs
	OIDData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	OIDAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Digest Algorithms
	OIDDigestAlgorithmMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	OIDDigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}

	OIDDigestAlgorithmECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDDigestAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDDigestAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDDigestAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// Signature algorithms from RFC 8017 appendix A.2.4 and RSASSA-PSS from RFC 4055
	OIDEncryptionAlgorithmRSAMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	OIDEncryptionAlgorithmRSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDEncryptionAlgorithmRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDEncryptionAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDEncryptionAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDEncryptionAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDEncryptionAlgorithmRSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}

	OIDEncryptionAlgorithmECDSAP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDEncryptionAlgorithmECDSAP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDEncryptionAlgorithmECDSAP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// Asymmetric encryption algorithms and their parameters from RFC 8017 appendices A.2 and B.2
	OIDEncryptionAlgorithmRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDEncryptionAlgorithmRSAESOAEP = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	OIDMaskGenerationFunctionMGF1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	OIDOAEPSourcePSpecified         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}

	// Symmetric encryption algorithms from RFC 8018 appendix B.2 and RFC 3565 section 4.1
	OIDEncryptionAlgorithmDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	OIDEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	OIDEncryptionAlgorithmAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDEncryptionAlgorithmAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OIDEncryptionAlgorithmAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// digestAlgorithms maps the digest algorithm identifiers this package accepts to their hashes.
var digestAlgorithms = []struct {
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}{
	{OIDDigestAlgorithmMD5, crypto.MD5},
	{OIDDigestAlgorithmSHA1, crypto.SHA1},
	{OIDDigestAlgorithmSHA224, crypto.SHA224},
	{OIDDigestAlgorithmSHA256, crypto.SHA256},
	{OIDDigestAlgorithmSHA384, crypto.SHA384},
	{OIDDigestAlgorithmSHA512, crypto.SHA512},
}

// getHashForOID returns the hash for a digest algorithm identifier.
func getHashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	for _, d := range digestAlgorithms {
		if oid.Equal(d.oid) {
			return d.hash, nil
		}
	}
	return 0, fmt.Errorf("pkcs7: unsupported digest algorithm %v", oid)
}

// getDigestOIDForHash returns the digest algorithm identifier for a hash.
func getDigestOIDForHash(hash crypto.Hash) (asn1.ObjectIdentifier, error) {
	for _, d := range digestAlgorithms {
		if d.hash == hash {
			return d.oid, nil
		}
	}
	return nil, fmt.Errorf("pkcs7: unsupported digest algorithm %v", hash)
}

// rsaSignatureAlgorithms maps a digest to the PKCS #1 v1.5 signature algorithm identifier that
// names it.
var rsaSignatureAlgorithms = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.MD5:    OIDEncryptionAlgorithmRSAMD5,
	crypto.SHA1:   OIDEncryptionAlgorithmRSASHA1,
	crypto.SHA224: OIDEncryptionAlgorithmRSASHA224,
	crypto.SHA256: OIDEncryptionAlgorithmRSASHA256,
	crypto.SHA384: OIDEncryptionAlgorithmRSASHA384,
	crypto.SHA512: OIDEncryptionAlgorithmRSASHA512,
}

// ecdsaSignatureAlgorithms maps a digest to the ECDSA signature algorithm identifier that names it.
var ecdsaSignatureAlgorithms = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   OIDDigestAlgorithmECDSASHA1,
	crypto.SHA256: OIDDigestAlgorithmECDSASHA256,
	crypto.SHA384: OIDDigestAlgorithmECDSASHA384,
	crypto.SHA512: OIDDigestAlgorithmECDSASHA512,
}

// getOIDForEncryptionAlgorithm returns the signerInfo signature algorithm identifier for a signer
// public key and digest.
func getOIDForEncryptionAlgorithm(pub crypto.PublicKey, hash crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		if oid, ok := rsaSignatureAlgorithms[hash]; ok {
			return oid, nil
		}
	case *ecdsa.PublicKey:
		if oid, ok := ecdsaSignatureAlgorithms[hash]; ok {
			return oid, nil
		}
	default:
		return nil, fmt.Errorf("pkcs7: unsupported signer key type %T", pub)
	}
	return nil, fmt.Errorf("pkcs7: digest %v cannot be used with signer key type %T", hash, pub)
}

// ParseOptions controls how ParseWithOptions decodes a message.
type ParseOptions struct {
	// LegacyCertificateParser retries embedded certificates that crypto/x509 refuses because their
	// authority key identifier extension is marked critical, using a copy of the Go 1.23 parser that
	// skips that check. Windows SCEP clients send such certificates. RFC 5280 forbids the critical
	// flag, so enable this only where those clients must be served.
	// See https://go-review.googlesource.com/c/go/+/562341.
	LegacyCertificateParser bool
}

// Parse decodes a BER or DER encoded CMS ContentInfo with the default ParseOptions.
func Parse(data []byte) (*PKCS7, error) {
	return ParseWithOptions(data, ParseOptions{})
}

// ParseWithOptions decodes a BER or DER encoded CMS ContentInfo. The input must hold exactly one
// ContentInfo.
func ParseWithOptions(data []byte, opts ParseOptions) (*PKCS7, error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}
	var info contentInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}

	switch {
	case info.ContentType.Equal(OIDSignedData):
		return parseSignedData(info.Content.Bytes, opts)
	case info.ContentType.Equal(OIDEnvelopedData):
		return parseEnvelopedData(info.Content.Bytes)
	case info.ContentType.Equal(OIDEncryptedData):
		return parseEncryptedData(info.Content.Bytes)
	}
	return nil, ErrUnsupportedContentType
}

// parseEnvelopedData decodes the content of an EnvelopedData ContentInfo.
func parseEnvelopedData(data []byte) (*PKCS7, error) {
	var ed envelopedData
	rest, err := asn1.Unmarshal(data, &ed)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data after EnvelopedData"}
	}
	return &PKCS7{raw: ed}, nil
}

// parseEncryptedData decodes the content of an EncryptedData ContentInfo.
func parseEncryptedData(data []byte) (*PKCS7, error) {
	var ed encryptedData
	rest, err := asn1.Unmarshal(data, &ed)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data after EncryptedData"}
	}
	return &PKCS7{raw: ed}, nil
}

// errCriticalAuthorityKeyID is the crypto/x509 error that LegacyCertificateParser works around.
const errCriticalAuthorityKeyID = "x509: authority key identifier incorrectly marked critical"

// Parse decodes the certificates of a SignedData certificate set.
func (raw rawCertificates) Parse(legacyFallback bool) ([]*x509.Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	certificates, err := x509.ParseCertificates(val.Bytes)
	if err != nil && legacyFallback && err.Error() == errCriticalAuthorityKeyID {
		certificates, err = legacyx509.ParseCertificates(val.Bytes)
	}

	return certificates, err
}

// isCertMatchForIssuerAndSerial reports whether cert carries the issuer and serial number.
func isCertMatchForIssuerAndSerial(cert *x509.Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes)
}

// Attribute represents a key value pair attribute. Value must be marshalable by
// `encoding/asn1`.
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value any
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []any
}

// Add appends an attribute, keeping insertion order until ForMarshalling sorts the set.
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value any) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

// Len implements sort.Interface.
func (sa attributeSet) Len() int {
	return len(sa)
}

// Less orders attributes by their DER encoding, as DER requires for a SET OF.
func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

// Swap implements sort.Interface.
func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

// Attributes returns the attributes in their current order.
func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

// ForMarshalling encodes every attribute value and returns the attributes in DER SET OF order.
func (attrs *attributes) ForMarshalling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: asn1Value},
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}
