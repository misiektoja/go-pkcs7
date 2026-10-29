package pkcs7

import (
	"bytes"
	"crypto"
	"testing"
)

// FuzzBer2Der checks that the converter never panics and that its output is a fixed point.
func FuzzBer2Der(f *testing.F) {
	f.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00})
	f.Add([]byte{0x30, 0x80, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x1F, 0x81, 0x00, 0x01, 0x41})
	f.Add([]byte{0x24, 0x80, 0x04, 0x01, 0x61, 0x04, 0x01, 0x62, 0x00, 0x00})
	f.Add(mustDecodePEM([]byte(testPKCS7)))
	f.Fuzz(func(t *testing.T, in []byte) {
		der, err := ber2der(in)
		if err != nil {
			return
		}
		again, err := ber2der(der)
		if err != nil {
			t.Fatalf("ber2der rejected its own output % X: %v", der, err)
		}
		if !bytes.Equal(der, again) {
			t.Fatalf("ber2der output is not stable:\n% X\n% X", der, again)
		}
	})
}

// FuzzParse checks that parsing, signature verification and decryption of hostile input return
// errors instead of panicking.
func FuzzParse(f *testing.F) {
	for _, fixture := range []string{SignedTestFixture, EncryptedTestFixture, RSAOAEPSHA256EncryptedTestFixture, AppStoreReceiptFixture} {
		f.Add(UnmarshalTestFixture(fixture).Input)
	}
	f.Add(mustDecodePEM([]byte(testPKCS7)))
	recipient := UnmarshalTestFixture(EncryptedTestFixture)
	f.Fuzz(func(_ *testing.T, in []byte) {
		p7, err := ParseWithOptions(in, ParseOptions{LegacyCertificateParser: true})
		if err != nil {
			return
		}
		_ = p7.Verify(VerifyOptions{AllowMD5: true})
		var value []byte
		_ = p7.UnmarshalSignedAttribute(OIDAttributeMessageDigest, &value)
		_, _ = p7.ContentEncryptionAlgorithm()
		_, _ = p7.Decrypt(recipient.Certificate, crypto.Decrypter(recipient.PrivateKey), allContentAlgorithms)
		_, _ = p7.DecryptUsingPSK(make([]byte, 16), allContentAlgorithms)
	})
}
