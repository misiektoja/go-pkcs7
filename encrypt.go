package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
)

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

// ContentEncryptionAlgorithm identifies the symmetric cipher that encrypts EnvelopedData and
// EncryptedData content. The zero value selects AES128CBC.
type ContentEncryptionAlgorithm int

const (
	// AES128CBC is AES with a 128-bit key in CBC mode. SCEP (RFC 8894) requires it.
	AES128CBC ContentEncryptionAlgorithm = iota + 1
	// AES192CBC is AES with a 192-bit key in CBC mode.
	AES192CBC
	// AES256CBC is AES with a 256-bit key in CBC mode.
	AES256CBC
	// DESEDE3CBC is three-key triple DES in CBC mode, for clients that predate AES.
	DESEDE3CBC
	// DESCBC is single DES in CBC mode. Its 56-bit key is broken. Decryption refuses it unless
	// DecryptOptions lists it.
	DESCBC
)

// contentCipher describes one content encryption algorithm.
type contentCipher struct {
	name     string
	oid      asn1.ObjectIdentifier
	keyLen   int
	newBlock func(key []byte) (cipher.Block, error)
}

// contentCiphers holds every content encryption algorithm this package implements.
var contentCiphers = map[ContentEncryptionAlgorithm]contentCipher{
	AES128CBC:  {"AES-128-CBC", OIDEncryptionAlgorithmAES128CBC, 16, aes.NewCipher},
	AES192CBC:  {"AES-192-CBC", OIDEncryptionAlgorithmAES192CBC, 24, aes.NewCipher},
	AES256CBC:  {"AES-256-CBC", OIDEncryptionAlgorithmAES256CBC, 32, aes.NewCipher},
	DESEDE3CBC: {"DES-EDE3-CBC", OIDEncryptionAlgorithmDESEDE3CBC, 24, des.NewTripleDESCipher},
	DESCBC:     {"DES-CBC", OIDEncryptionAlgorithmDESCBC, 8, des.NewCipher},
}

// String returns the OpenSSL-style name of the algorithm.
func (a ContentEncryptionAlgorithm) String() string {
	if c, ok := contentCiphers[a]; ok {
		return c.name
	}
	return fmt.Sprintf("ContentEncryptionAlgorithm(%d)", int(a))
}

// contentEncryptionAlgorithmForOID returns the algorithm an identifier names.
func contentEncryptionAlgorithmForOID(oid asn1.ObjectIdentifier) (ContentEncryptionAlgorithm, bool) {
	for alg, c := range contentCiphers {
		if c.oid.Equal(oid) {
			return alg, true
		}
	}
	return 0, false
}

// KeyEncryptionAlgorithm identifies how the content key is encrypted for an RSA recipient. The zero
// value selects RSAPKCS1v15.
type KeyEncryptionAlgorithm int

const (
	// RSAPKCS1v15 is RSAES-PKCS1-v1_5 key transport. SCEP clients expect it.
	RSAPKCS1v15 KeyEncryptionAlgorithm = iota + 1
	// RSAOAEP is RSAES-OAEP key transport (RFC 8017) with MGF1 over EncryptOptions.OAEPHash.
	RSAOAEP
)

// String returns the name of the algorithm.
func (a KeyEncryptionAlgorithm) String() string {
	switch a {
	case RSAPKCS1v15:
		return "RSAES-PKCS1-v1_5"
	case RSAOAEP:
		return "RSAES-OAEP"
	}
	return fmt.Sprintf("KeyEncryptionAlgorithm(%d)", int(a))
}

// EncryptOptions selects the algorithms Encrypt and EncryptUsingPSK use.
type EncryptOptions struct {
	// ContentEncryption is the content cipher. The zero value selects AES128CBC.
	ContentEncryption ContentEncryptionAlgorithm

	// KeyEncryption is the RSA key transport for each recipient. The zero value selects RSAPKCS1v15.
	// EncryptUsingPSK ignores it.
	KeyEncryption KeyEncryptionAlgorithm

	// OAEPHash is the RSAES-OAEP hash and MGF1 hash. The zero value selects SHA-256.
	OAEPHash crypto.Hash
}

// contentCipher returns the content cipher the options select.
func (opts EncryptOptions) contentCipher() (contentCipher, error) {
	alg := opts.ContentEncryption
	if alg == 0 {
		alg = AES128CBC
	}
	c, ok := contentCiphers[alg]
	if !ok {
		return contentCipher{}, ErrUnsupportedEncryptionAlgorithm
	}
	return c, nil
}

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New(
	"pkcs7: cannot encrypt content: only AES-CBC, DES-EDE3-CBC and DES-CBC are supported",
)

// ErrUnsupportedKeyEncryptionAlgorithm is returned when an
// unsupported key encryption algorithm is requested.
var ErrUnsupportedKeyEncryptionAlgorithm = errors.New("pkcs7: unsupported key encryption algorithm provided")

// ErrUnsupportedKeyEncryptionHash is returned when an
// unsupported key encryption hash is provided.
var ErrUnsupportedKeyEncryptionHash = errors.New("pkcs7: unsupported key encryption hash provided")

// ErrPSKNotProvided is returned when attempting to encrypt
// using a PSK without actually providing the PSK.
var ErrPSKNotProvided = errors.New("pkcs7: cannot encrypt content: PSK not provided")

// encryptCBC pads and encrypts content in CBC mode under key with a random IV.
func encryptCBC(c contentCipher, content, key []byte) (*encryptedContentInfo, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	plaintext, err := pad(content, block.BlockSize())
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return &encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  c.oid,
			Parameters: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}, nil
}

// Encrypt creates an EnvelopedData message whose content key is encrypted for each recipient
// certificate. Recipients must hold RSA keys.
func Encrypt(content []byte, recipients []*x509.Certificate, opts EncryptOptions) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("pkcs7: no recipients")
	}
	c, err := opts.contentCipher()
	if err != nil {
		return nil, err
	}
	kea, err := opts.keyEncryptionAlgorithm()
	if err != nil {
		return nil, err
	}
	key := make([]byte, c.keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	eci, err := encryptCBC(c, content, key)
	if err != nil {
		return nil, err
	}

	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKey(key, recipient, opts)
		if err != nil {
			return nil, err
		}
		recipientInfos[i] = recipientInfo{
			Version:                0,
			IssuerAndSerialNumber:  cert2issuerAndSerial(recipient),
			KeyEncryptionAlgorithm: kea,
			EncryptedKey:           encrypted,
		}
	}

	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}
	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	wrapper := contentInfo{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}
	return asn1.Marshal(wrapper)
}

// rsaOAEPParameters is RSAES-OAEP-params from RFC 8017 appendix A.2.1.
type rsaOAEPParameters struct {
	Hash    pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MGF     pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	PSource pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
}

// oaepHash returns the RSAES-OAEP hash the options select.
func (opts EncryptOptions) oaepHash() (crypto.Hash, error) {
	hash := opts.OAEPHash
	if hash == 0 {
		hash = crypto.SHA256
	}
	switch hash {
	case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return hash, nil
	default:
		return 0, ErrUnsupportedKeyEncryptionHash
	}
}

// keyEncryptionAlgorithm returns the recipientInfo key encryption algorithm identifier.
func (opts EncryptOptions) keyEncryptionAlgorithm() (pkix.AlgorithmIdentifier, error) {
	switch opts.KeyEncryption {
	case 0, RSAPKCS1v15:
		return pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmRSA, Parameters: asn1.NullRawValue}, nil
	case RSAOAEP:
		hash, err := opts.oaepHash()
		if err != nil {
			return pkix.AlgorithmIdentifier{}, err
		}
		hashOID, err := getDigestOIDForHash(hash)
		if err != nil {
			return pkix.AlgorithmIdentifier{}, err
		}
		// The MGF1 hash is written out because its default is SHA-1, while crypto/rsa uses the
		// OAEP hash for MGF1 too.
		mgfParams, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: hashOID})
		if err != nil {
			return pkix.AlgorithmIdentifier{}, err
		}
		params := rsaOAEPParameters{
			Hash: pkix.AlgorithmIdentifier{Algorithm: hashOID},
			MGF: pkix.AlgorithmIdentifier{
				Algorithm:  OIDMaskGenerationFunctionMGF1,
				Parameters: asn1.RawValue{FullBytes: mgfParams},
			},
		}
		encoded, err := asn1.Marshal(params)
		if err != nil {
			return pkix.AlgorithmIdentifier{}, err
		}
		return pkix.AlgorithmIdentifier{
			Algorithm:  OIDEncryptionAlgorithmRSAESOAEP,
			Parameters: asn1.RawValue{FullBytes: encoded},
		}, nil
	}
	return pkix.AlgorithmIdentifier{}, ErrUnsupportedKeyEncryptionAlgorithm
}

// EncryptUsingPSK creates an EncryptedData message whose content is encrypted with the pre-shared
// key. The key length must match the content cipher.
func EncryptUsingPSK(content []byte, key []byte, opts EncryptOptions) ([]byte, error) {
	if key == nil {
		return nil, ErrPSKNotProvided
	}
	c, err := opts.contentCipher()
	if err != nil {
		return nil, err
	}
	if len(key) != c.keyLen {
		return nil, fmt.Errorf("pkcs7: %s needs a %d-byte key, got %d bytes", c.name, c.keyLen, len(key))
	}
	eci, err := encryptCBC(c, content, key)
	if err != nil {
		return nil, err
	}

	ed := encryptedData{
		Version:              0,
		EncryptedContentInfo: *eci,
	}
	innerContent, err := asn1.Marshal(ed)
	if err != nil {
		return nil, err
	}
	wrapper := contentInfo{
		ContentType: OIDEncryptedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}
	return asn1.Marshal(wrapper)
}

// marshalEncryptedContent wraps ciphertext in the implicit [0] encryptedContent field.
func marshalEncryptedContent(content []byte) asn1.RawValue {
	return asn1.RawValue{Bytes: content, Class: 2, IsCompound: false}
}

// encryptKey encrypts the content key for one RSA recipient.
func encryptKey(key []byte, recipient *x509.Certificate, opts EncryptOptions) ([]byte, error) {
	pub, ok := recipient.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrUnsupportedKeyType
	}
	switch opts.KeyEncryption {
	case 0, RSAPKCS1v15:
		// SCEP and older CMS peers need PKCS #1 v1.5 key transport, which Go has deprecated.
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key) //nolint:staticcheck // See above.
	case RSAOAEP:
		hash, err := opts.oaepHash()
		if err != nil {
			return nil, err
		}
		return rsa.EncryptOAEP(hash.New(), rand.Reader, pub, key, nil)
	}
	return nil, ErrUnsupportedKeyEncryptionAlgorithm
}

// pad appends PKCS #7 padding (RFC 5652 section 6.3) up to a multiple of blocklen.
func pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 || blocklen > 255 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	padding := bytes.Repeat([]byte{byte(padlen)}, padlen) //nolint:gosec // padlen is at most blocklen, which is below 256.
	return append(slices.Clip(data), padding...), nil
}
