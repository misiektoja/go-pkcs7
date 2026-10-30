package pkcs7

import (
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// ErrUnsupportedAlgorithm is returned when the content cipher of a message is not implemented.
var ErrUnsupportedAlgorithm = errors.New(
	"pkcs7: cannot decrypt data: only AES-CBC, DES-EDE3-CBC and DES-CBC are supported",
)

// ErrUnsupportedAsymmetricEncryptionAlgorithm is returned when a recipient uses an unknown key
// encryption algorithm.
var ErrUnsupportedAsymmetricEncryptionAlgorithm = errors.New(
	"pkcs7: cannot decrypt data: only RSA PKCS#1 v1.5 and RSA OAEP are supported",
)

// ErrUnsupportedKeyType is returned when attempting to encrypting keys using a key that's not an RSA key
var ErrUnsupportedKeyType = errors.New("pkcs7: only RSA keys are supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is not an encrypted data type")

// ErrContentEncryptionNotAllowed is returned when DecryptOptions do not accept the content cipher
// of a message.
var ErrContentEncryptionNotAllowed = errors.New("pkcs7: content encryption algorithm is not allowed")

// ErrDecryptionFailed is returned when the content key or the content cannot be decrypted. It does
// not say which step failed, so that a sender cannot use the error as a padding oracle.
var ErrDecryptionFailed = errors.New("pkcs7: decryption failed")

// DecryptOptions controls which algorithms Decrypt and DecryptUsingPSK accept.
type DecryptOptions struct {
	// ContentEncryptionAlgorithms lists the content ciphers to accept. When empty,
	// DefaultContentDecryptionAlgorithms applies, which leaves out single DES.
	ContentEncryptionAlgorithms []ContentEncryptionAlgorithm
}

// DefaultContentDecryptionAlgorithms are the content ciphers accepted when DecryptOptions lists none.
var DefaultContentDecryptionAlgorithms = []ContentEncryptionAlgorithm{AES128CBC, AES192CBC, AES256CBC, DESEDE3CBC}

// allows reports whether the options accept the content cipher.
func (opts DecryptOptions) allows(alg ContentEncryptionAlgorithm) bool {
	if len(opts.ContentEncryptionAlgorithms) == 0 {
		return slices.Contains(DefaultContentDecryptionAlgorithms, alg)
	}
	return slices.Contains(opts.ContentEncryptionAlgorithms, alg)
}

// ContentEncryptionAlgorithm returns the content cipher of an EnvelopedData or EncryptedData
// message. A responder can use it to answer with the cipher the requester chose.
func (p7 *PKCS7) ContentEncryptionAlgorithm() (ContentEncryptionAlgorithm, error) {
	var eci encryptedContentInfo
	switch data := p7.raw.(type) {
	case envelopedData:
		eci = data.EncryptedContentInfo
	case encryptedData:
		eci = data.EncryptedContentInfo
	default:
		return 0, ErrNotEncryptedContent
	}
	alg, ok := contentEncryptionAlgorithmForOID(eci.ContentEncryptionAlgorithm.Algorithm)
	if !ok {
		return 0, ErrUnsupportedAlgorithm
	}
	return alg, nil
}

// Recipient identifies a recipient of an EnvelopedData message by the issuer name and serial
// number of its certificate.
type Recipient struct {
	// Issuer is the DER encoded issuer name.
	Issuer []byte
	// SerialNumber is the certificate serial number.
	SerialNumber *big.Int
}

// Recipients lists the recipients of an EnvelopedData message, so a receiver that holds several
// keys can choose the one that decrypts it. They come in encoded order. DER sorts the recipient
// set, so the order need not match the certificates given to Encrypt.
func (p7 *PKCS7) Recipients() ([]Recipient, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipients := make([]Recipient, 0, len(data.RecipientInfos))
	for _, info := range data.RecipientInfos {
		recipients = append(recipients, Recipient{
			Issuer:       info.IssuerAndSerialNumber.IssuerName.FullBytes,
			SerialNumber: info.IssuerAndSerialNumber.SerialNumber,
		})
	}
	return recipients, nil
}

// Decrypt decrypts EnvelopedData content for the recipient certificate with its RSA private key.
func (p7 *PKCS7) Decrypt(cert *x509.Certificate, key crypto.Decrypter, opts DecryptOptions) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient, ok := selectRecipientForCertificate(data.RecipientInfos, cert)
	if !ok {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	c, err := data.EncryptedContentInfo.contentCipher(opts)
	if err != nil {
		return nil, err
	}
	var decrypterOpts crypto.DecrypterOpts
	switch algorithm := recipient.KeyEncryptionAlgorithm.Algorithm; {
	case algorithm.Equal(OIDEncryptionAlgorithmRSAESOAEP):
		if decrypterOpts, err = parseOAEPParameters(recipient.KeyEncryptionAlgorithm.Parameters); err != nil {
			return nil, err
		}
	case algorithm.Equal(OIDEncryptionAlgorithmRSA):
		// With SessionKeyLen set, bad padding yields a random key of the right length instead of an
		// error. Content decryption then fails like it does for any wrong key, which defeats
		// Bleichenbacher's attack (RFC 3218 section 2.3.2). SCEP and older CMS peers need PKCS #1 v1.5
		// key transport, which Go has deprecated.
		decrypterOpts = &rsa.PKCS1v15DecryptOptions{SessionKeyLen: c.keyLen} //nolint:staticcheck // See above.
	default:
		return nil, ErrUnsupportedAsymmetricEncryptionAlgorithm
	}
	contentKey, err := key.Decrypt(rand.Reader, recipient.EncryptedKey, decrypterOpts)
	if err != nil || len(contentKey) != c.keyLen {
		return nil, ErrDecryptionFailed
	}
	return data.EncryptedContentInfo.decrypt(c, contentKey)
}

// parseOAEPParameters decodes RSAES-OAEP parameters into decryption options. Absent fields take
// the SHA-1 defaults from RFC 8017.
func parseOAEPParameters(params asn1.RawValue) (*rsa.OAEPOptions, error) {
	var p rsaOAEPParameters
	if len(params.FullBytes) > 0 && !slices.Equal(params.FullBytes, asn1.NullBytes) {
		rest, err := asn1.Unmarshal(params.FullBytes, &p)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: failed unmarshaling key encryption algorithm parameters: %w", err)
		}
		if len(rest) != 0 {
			return nil, errors.New("pkcs7: trailing data after RSA OAEP parameters")
		}
	}
	hash, mgfHash, err := parseHashAndMGF(p.Hash, p.MGF)
	if err != nil {
		return nil, err
	}
	var label []byte
	if len(p.PSource.Algorithm) > 0 {
		if !p.PSource.Algorithm.Equal(OIDOAEPSourcePSpecified) {
			return nil, fmt.Errorf("pkcs7: unsupported RSA OAEP label source %v", p.PSource.Algorithm)
		}
		if _, err := asn1.Unmarshal(p.PSource.Parameters.FullBytes, &label); err != nil {
			return nil, errors.New("pkcs7: malformed RSA OAEP label")
		}
	}
	return &rsa.OAEPOptions{Hash: hash, MGFHash: mgfHash, Label: label}, nil
}

// DecryptUsingPSK decrypts EncryptedData content with a pre-shared key.
func (p7 *PKCS7) DecryptUsingPSK(key []byte, opts DecryptOptions) ([]byte, error) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	c, err := data.EncryptedContentInfo.contentCipher(opts)
	if err != nil {
		return nil, err
	}
	if len(key) != c.keyLen {
		return nil, fmt.Errorf("pkcs7: %s needs a %d-byte key, got %d bytes", c.name, c.keyLen, len(key))
	}
	return data.EncryptedContentInfo.decrypt(c, key)
}

// contentCipher returns the content cipher of the message when the options accept it.
func (eci encryptedContentInfo) contentCipher(opts DecryptOptions) (contentCipher, error) {
	alg, ok := contentEncryptionAlgorithmForOID(eci.ContentEncryptionAlgorithm.Algorithm)
	if !ok {
		return contentCipher{}, ErrUnsupportedAlgorithm
	}
	if !opts.allows(alg) {
		return contentCipher{}, fmt.Errorf("%w: %s", ErrContentEncryptionNotAllowed, alg)
	}
	return contentCiphers[alg], nil
}

// decrypt decrypts the CBC content with the content key and removes its padding.
func (eci encryptedContentInfo) decrypt(c contentCipher, key []byte) ([]byte, error) {
	ciphertext := eci.EncryptedContent.Bytes
	// The encrypted content is either one implicitly tagged OCTET STRING or, in BER, a
	// constructed one made of segments.
	if eci.EncryptedContent.IsCompound {
		var err error
		if ciphertext, err = joinOctetStrings(eci.EncryptedContent.Bytes); err != nil {
			return nil, err
		}
	}

	block, err := c.newBlock(key)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	params := eci.ContentEncryptionAlgorithm.Parameters
	if params.Class != asn1.ClassUniversal || params.Tag != asn1.TagOctetString || params.IsCompound ||
		len(params.Bytes) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return nil, errors.New("pkcs7: ciphertext is not a whole number of cipher blocks")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, params.Bytes).CryptBlocks(plaintext, ciphertext)
	return unpad(plaintext, block.BlockSize())
}

// unpad removes PKCS #7 padding in constant time. Every padding failure returns ErrDecryptionFailed.
func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 || blocklen > 255 {
		return nil, fmt.Errorf("pkcs7: invalid blocklen %d", blocklen)
	}
	if len(data) == 0 || len(data)%blocklen != 0 {
		return nil, ErrDecryptionFailed
	}
	padByte := data[len(data)-1]
	padlen := int(padByte)
	good := subtle.ConstantTimeLessOrEq(1, padlen) & subtle.ConstantTimeLessOrEq(padlen, blocklen)
	// Every byte of the last block is inspected, so the time taken does not depend on padlen.
	for i := 1; i <= blocklen; i++ {
		inPadding := subtle.ConstantTimeLessOrEq(i, padlen)
		good &= subtle.ConstantTimeSelect(inPadding, subtle.ConstantTimeByteEq(data[len(data)-i], padByte), 1)
	}
	if good != 1 {
		return nil, ErrDecryptionFailed
	}
	return data[:len(data)-padlen], nil
}

// selectRecipientForCertificate returns the recipient info addressed to cert.
func selectRecipientForCertificate(recipients []recipientInfo, cert *x509.Certificate) (recipientInfo, bool) {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp, true
		}
	}
	return recipientInfo{}, false
}
