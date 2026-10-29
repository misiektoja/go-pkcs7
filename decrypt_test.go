package pkcs7

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
)

// TestDecrypt decrypts messages that OpenSSL produced with each key transport.
func TestDecrypt(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected string
	}{
		{
			name:     "rsa-pkcs-#1-v1.5/1",
			fixture:  EncryptedTestFixture,
			expected: "This is a test",
		},
		{
			name:     "rsa-pkcs-#1-v1.5/2",
			fixture:  RSAPKCS1v15EncryptedTestFixture,
			expected: "This is a test",
		},
		{
			name:     "rsa-oaep-sha1",
			fixture:  RSAOAEPSHA1EncryptedTestFixture,
			expected: "This is a test",
		},
		{
			name:     "rsa-oaep-sha256",
			fixture:  RSAOAEPSHA256EncryptedTestFixture,
			expected: "This is a test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := UnmarshalTestFixture(tt.fixture)
			p7, err := Parse(fixture.Input)
			if err != nil {
				t.Fatal(err)
			}
			content, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey, DecryptOptions{})
			if err != nil {
				t.Errorf("cannot Decrypt with error: %v", err)
			}
			if !bytes.Equal(content, []byte(tt.expected)) {
				t.Errorf("decrypted result does not match.\n\tExpected:%s\n\tActual:%s", []byte(tt.expected), content)
			}
		})
	}
}

// TestUnpad covers PKCS #7 padding removal for 8-byte and 16-byte blocks.
func TestUnpad(t *testing.T) {
	t.Parallel()
	for _, blockSize := range []int{8, 16} {
		for _, tt := range []struct {
			name    string
			data    []byte
			want    []byte
			wantErr bool
		}{
			{"empty", nil, nil, true},
			{"unaligned", make([]byte, blockSize-1), nil, true},
			{"zero padding byte", make([]byte, blockSize), nil, true},
			{"padding longer than the input", bytes.Repeat([]byte{255}, blockSize), nil, true},
			{"padding longer than a block", bytes.Repeat([]byte{byte(blockSize + 1)}, 2*blockSize), nil, true},
			{"inconsistent padding", append(make([]byte, blockSize-1), 2), nil, true},
			{"one padding byte", append(make([]byte, blockSize-1), 1), make([]byte, blockSize-1), false},
			{"a whole block of padding", bytes.Repeat([]byte{byte(blockSize)}, blockSize), []byte{}, false},
		} {
			got, err := unpad(tt.data, blockSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("%d/%s: unpad error = %v, want error %v", blockSize, tt.name, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrDecryptionFailed) {
				t.Errorf("%d/%s: unpad error = %v, want ErrDecryptionFailed", blockSize, tt.name, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("%d/%s: unpad = % X, want % X", blockSize, tt.name, got, tt.want)
			}
		}
	}
	if _, err := unpad([]byte{1}, 0); err == nil {
		t.Error("unpad accepted a zero block size")
	}
}

// encryptedFixture builds an EnvelopedData message for the test certificate whose encrypted
// content and IV the caller chooses, so tests can feed Decrypt malformed ciphertext.
func encryptedFixture(t *testing.T, cert *x509.Certificate, alg asn1.ObjectIdentifier, key, iv, ciphertext []byte) *PKCS7 {
	t.Helper()
	wrapped, err := rsa.EncryptPKCS1v15(rand.Reader, cert.PublicKey.(*rsa.PublicKey), key) //nolint:staticcheck // the fixture needs PKCS #1 v1.5 key transport.
	if err != nil {
		t.Fatal(err)
	}
	ed := envelopedData{
		RecipientInfos: []recipientInfo{{
			IssuerAndSerialNumber:  cert2issuerAndSerial(cert),
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDEncryptionAlgorithmRSA, Parameters: asn1.NullRawValue},
			EncryptedKey:           wrapped,
		}},
		EncryptedContentInfo: encryptedContentInfo{
			ContentType:                OIDData,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: alg, Parameters: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: iv}},
			EncryptedContent:           marshalEncryptedContent(ciphertext),
		},
	}
	inner, err := asn1.Marshal(ed)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(contentInfo{ContentType: OIDEnvelopedData, Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	return p7
}

// TestDecryptPadding checks that bad CBC padding and partial blocks are refused after decryption.
func TestDecryptPadding(t *testing.T) {
	t.Parallel()
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	key := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		last    byte
		length  int
		wantErr string
	}{
		{"valid", 1, aes.BlockSize, ""},
		{"padding byte 255", 255, aes.BlockSize, "decryption failed"},
		{"padding byte 0", 0, aes.BlockSize, "decryption failed"},
		{"partial block", 1, aes.BlockSize + 3, "whole number of cipher blocks"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := make([]byte, aes.BlockSize)
			plaintext[len(plaintext)-1] = tt.last
			ciphertext := make([]byte, tt.length)
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext[:aes.BlockSize], plaintext)
			p7 := encryptedFixture(t, fixture.Certificate, OIDEncryptionAlgorithmAES128CBC, key, iv, ciphertext)
			got, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey, DecryptOptions{})
			if tt.wantErr == "" {
				if err != nil || !bytes.Equal(got, plaintext[:len(plaintext)-1]) {
					t.Fatalf("Decrypt = % X, %v", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Decrypt error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestDecryptRejects covers inputs Decrypt must refuse without revealing which step failed.
func TestDecryptRejects(t *testing.T) {
	t.Parallel()
	fixture := UnmarshalTestFixture(EncryptedTestFixture)
	plaintext := []byte("This is a test")

	desMessage, err := Encrypt(plaintext, []*x509.Certificate{fixture.Certificate}, EncryptOptions{ContentEncryption: DESCBC})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(desMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey, DecryptOptions{}); !errors.Is(err, ErrContentEncryptionNotAllowed) {
		t.Errorf("single DES by default: error = %v, want a refusal", err)
	}
	if got, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey, DecryptOptions{ContentEncryptionAlgorithms: []ContentEncryptionAlgorithm{DESCBC}}); err != nil || !bytes.Equal(got, plaintext) {
		t.Errorf("single DES when allowed: Decrypt = %q, %v", got, err)
	}

	aesMessage, err := Encrypt(plaintext, []*x509.Certificate{fixture.Certificate}, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p7, err = Parse(aesMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p7.Decrypt(fixture.Certificate, fixture.PrivateKey, DecryptOptions{ContentEncryptionAlgorithms: []ContentEncryptionAlgorithm{AES256CBC}}); err == nil {
		t.Error("AES-128-CBC was accepted although only AES-256-CBC was allowed")
	}

	// A corrupted encrypted key must look the same as a wrong key: the PKCS #1 v1.5 padding failure
	// is replaced by a random content key. Content decryption then reports the generic error or, when
	// the random key happens to yield valid padding, returns garbage.
	ed := p7.raw.(envelopedData)
	ed.RecipientInfos[0].EncryptedKey = bytes.Clone(ed.RecipientInfos[0].EncryptedKey)
	ed.RecipientInfos[0].EncryptedKey[10] ^= 0xff
	tampered := &PKCS7{raw: ed}
	got, err := tampered.Decrypt(fixture.Certificate, fixture.PrivateKey, DecryptOptions{})
	if (err == nil && bytes.Equal(got, plaintext)) || (err != nil && !errors.Is(err, ErrDecryptionFailed)) {
		t.Fatalf("corrupted key: Decrypt = %q, %v, want ErrDecryptionFailed or garbage", got, err)
	}

	other, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p7.Decrypt(other.Certificate, other.PrivateKey.(*rsa.PrivateKey), DecryptOptions{}); err == nil {
		t.Error("Decrypt succeeded for a certificate that is not a recipient")
	}
}

// TestRecipients checks that every recipient of an EnvelopedData message is listed by issuer and
// serial number, and that other content types are refused.
func TestRecipients(t *testing.T) {
	t.Parallel()
	first, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	certs := []*x509.Certificate{first.Certificate, second.Certificate}
	message, err := Encrypt([]byte("content"), certs, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(message)
	if err != nil {
		t.Fatal(err)
	}
	recipients, err := p7.Recipients()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != len(certs) {
		t.Fatalf("Recipients() returned %d recipients, want %d", len(recipients), len(certs))
	}
	for i, cert := range certs {
		if !bytes.Equal(recipients[i].Issuer, cert.RawIssuer) || recipients[i].SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Errorf("recipient %d does not identify certificate %d", i, i)
		}
	}

	signed, err := NewSignedData([]byte("content"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signed.AddSigner(first.Certificate, first.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if p7, err = Parse(der); err != nil {
		t.Fatal(err)
	}
	if _, err := p7.Recipients(); !errors.Is(err, ErrNotEncryptedContent) {
		t.Errorf("Recipients() on SignedData: error = %v, want ErrNotEncryptedContent", err)
	}
}

// TestContentEncryptionAlgorithmNames checks the names and the zero-value handling of the
// algorithm types.
func TestContentEncryptionAlgorithmNames(t *testing.T) {
	t.Parallel()
	if got := AES128CBC.String(); got != "AES-128-CBC" {
		t.Errorf("AES128CBC.String() = %q", got)
	}
	if got := ContentEncryptionAlgorithm(0).String(); got != "ContentEncryptionAlgorithm(0)" {
		t.Errorf("zero value String() = %q", got)
	}
	if got := KeyEncryptionAlgorithm(7).String(); got != "KeyEncryptionAlgorithm(7)" {
		t.Errorf("unknown key encryption String() = %q", got)
	}
}

// echo -n "This is a test" > test.txt
// openssl cms -encrypt -in test.txt cert.pem
var EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBGgYJKoZIhvcNAQcDoIIBCzCCAQcCAQAxgcwwgckCAQAwMjApMRAwDgYDVQQK
EwdBY21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmsCBQDL+CvWMA0GCSqGSIb3
DQEBAQUABIGAyFz7bfI2noUs4FpmYfztm1pVjGyB00p9x0H3gGHEYNXdqlq8VG8d
iq36poWtEkatnwsOlURWZYECSi0g5IAL0U9sj82EN0xssZNaK0S5FTGnB3DPvYgt
HJvcKq7YvNLKMh4oqd17C6GB4oXyEBDj0vZnL7SUoCAOAWELPeC8CTUwMwYJKoZI
hvcNAQcBMBQGCCqGSIb3DQMHBAhEowTkot3a7oAQFD//J/IhFnk+JbkH7HZQFA==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIB1jCCAUGgAwIBAgIFAMv4K9YwCwYJKoZIhvcNAQELMCkxEDAOBgNVBAoTB0Fj
bWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyazAeFw0xNTA1MDYwMzU2NDBaFw0x
NjA1MDYwMzU2NDBaMCUxEDAOBgNVBAoTB0FjbWUgQ28xETAPBgNVBAMTCEpvbiBT
bm93MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6NU0R0eiCYVquU4RcjKc
LzGfx0aa1lMr2TnLQUSeLFZHFxsyyMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg
8+Zg2r8xnnney7abxcuv0uATWSIeKlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP
+Zxp2ni5qHNraf3wE2VPIQIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCAKAwCwYJKoZI
hvcNAQELA4GBAIr2F7wsqmEU/J/kLyrCgEVXgaV/sKZq4pPNnzS0tBYk8fkV3V18
sBJyHKRLL/wFZASvzDcVGCplXyMdAOCyfd8jO3F9Ac/xdlz10RrHJT75hNu3a7/n
9KNwKhfN4A1CQv2x372oGjRhCW5bHNCWx4PIVeNzCyq/KZhyY9sxHE6f
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDK6NU0R0eiCYVquU4RcjKcLzGfx0aa1lMr2TnLQUSeLFZHFxsy
yMXXuMPig3HK4A7SGFHupO+/1H/sL4xpH5zg8+Zg2r8xnnney7abxcuv0uATWSIe
KlNnb1ZO1BAxFnESc3GtyOCr2dUwZHX5mRVP+Zxp2ni5qHNraf3wE2VPIQIDAQAB
AoGBALyvnSt7KUquDen7nXQtvJBudnf9KFPt//OjkdHHxNZNpoF/JCSqfQeoYkeu
MdAVYNLQGMiRifzZz4dDhA9xfUAuy7lcGQcMCxEQ1dwwuFaYkawbS0Tvy2PFlq2d
H5/HeDXU4EDJ3BZg0eYj2Bnkt1sJI35UKQSxblQ0MY2q0uFBAkEA5MMOogkgUx1C
67S1tFqMUSM8D0mZB0O5vOJZC5Gtt2Urju6vywge2ArExWRXlM2qGl8afFy2SgSv
Xk5eybcEiQJBAOMRwwbEoW5NYHuFFbSJyWll4n71CYuWuQOCzehDPyTb80WFZGLV
i91kFIjeERyq88eDE5xVB3ZuRiXqaShO/9kCQQCKOEkpInaDgZSjskZvuJ47kByD
6CYsO4GIXQMMeHML8ncFH7bb6AYq5ybJVb2NTU7QLFJmfeYuhvIm+xdOreRxAkEA
o5FC5Jg2FUfFzZSDmyZ6IONUsdF/i78KDV5nRv1R+hI6/oRlWNCtTNBv/lvBBd6b
dseUE9QoaQZsn5lpILEvmQJAZ0B+Or1rAYjnbjnUhdVZoy9kC4Zov+4UH3N/BtSy
KJRWUR0wTWfZBPZ5hAYZjTBEAFULaYCXlQKsODSp0M1aQA==
-----END RSA PRIVATE KEY-----`

//   - Generate new private key using openssl genrsa -out key.pem 2048
//   - Create a self-signed certificate for key.pem using
//     openssl req -x509 -key key.pem -out certificate.pem
//   - Create a file with the data to be encrypted using
//     echo -n "This is a test" > test.txt
//   - Generate PKCS #7 enveloped data encrypted using AES using
//     openssl smime -encrypt -in test.txt -aes256 -outform pem certificate.pem
var RSAPKCS1v15EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBwgYJKoZIhvcNAQcDoIIBszCCAa8CAQAxggFqMIIBZgIBADBOMDYxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMRIwEAYDVQQKDAlUZXN0IENlcnQC
FCoCAvxWlBvVDwodj5frshHwg0GSMA0GCSqGSIb3DQEBAQUABIIBABvjuG8mbhW6
SQkYvyfs3S8BQxQJwl1I/wLckEB8YClEItw4ZCsDXVodJpAtQ+fiQPRpQLMksD22
IXVxdRrAV2/Nzl1g8vLa1ae3zh9pQsEOf0pTzVIChB3WgQegOkpu88i6Vp/TNzUp
fYezUTVRgHC7cJMOciYMLVxgKRdjLVZeyaqKY6zU1OgKy0/JQpfRk6rlTyMltMDY
2mjywc/lP9GCNfMxpSpj/CpN+2YKYxKOdht3dpO5e13WWzhYmz7oUeLRN4AC9M4N
Cfa8qYh3ipJauxCT4qeBIIDidHSA9iP8h3Ro3d+7q9Imf1UjJvuDmc8A8UlFdTRE
r4tg/TnnVeAwPAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQ1Az0LE0/4y9NjXZ7
JSh3X4AQD6BD9BghuxT99dPWWkyRlw==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIUKgIC/FaUG9UPCh2Pl+uyEfCDQZIwDQYJKoZIhvcNAQEL
BQAwNjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxEjAQBgNVBAoM
CVRlc3QgQ2VydDAeFw0yMTAyMTAxNjIwMDBaFw0yMTAzMTIxNjIwMDBaMDYxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMRIwEAYDVQQKDAlUZXN0IENl
cnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDS+Nd7wSgX6j6xLCZd
SdwAq8BWlbruuFEf6VYvZ5FBzIOeTwFketD1tJie8tq9sEv8V8sFYlZruM4mA12G
jxSse5rwVTf6TomQChEuvW+l6dB4N7EQ6EtZ1bmBKUk0jhqmrHTgT8YbyBKZ/2t+
UqkcvmHIPBMUEHwEOqGjj+RsRb69qYZYWTbtUjBbEt2PBk2noVtd7yyqvtPUl/p0
LAhL9oAsZTgL4LiZaOo9NGV6AkJWYQJuONOXSkx34Sn6V7xLPLhD/FDv8q3X9WuP
dc00rlLDWpa2zn8dI3MNK+Q8KTi643f3MpfOiE0xuj13Hwp2QkfsgLdoER3OTFEK
UmedAgMBAAGjUzBRMB0GA1UdDgQWBBRaaQq4a4U1xwlriTHnfBq8X5ctvDAfBgNV
HSMEGDAWgBRaaQq4a4U1xwlriTHnfBq8X5ctvDAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQDFURgxrMBCmMVZFR9+jlCAK9T/tH3tX4d2iIVaj1Aj
dw0wDAO20QPM/ZHlPM+l8yMT8ACY5ZHp6neRcaz9qmNeYAeGVu5twIo30LfRWDoY
rfL3gIHeUXQCdxwJMh3z14WNdxPBoPXerw9LT1J97Dg81e/b+Za/vdRfqNIKbADj
yoP7LBNaX/r83/SsGGbtW618sar+27wWRlGeZvFq8hwh+qyj3S7wtY7wx5weR7eZ
S9K/MB9npTbIjDUidByTIhpk0hS55s1jF6U0wlmV0oUmC4wBIebyo1cL/CMPRv+a
z/D9/ZvUoaotiATRWSKLCmxapcmGbMxhHHYWYWtzPCt1
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0vjXe8EoF+o+sSwmXUncAKvAVpW67rhRH+lWL2eRQcyDnk8B
ZHrQ9bSYnvLavbBL/FfLBWJWa7jOJgNdho8UrHua8FU3+k6JkAoRLr1vpenQeDex
EOhLWdW5gSlJNI4apqx04E/GG8gSmf9rflKpHL5hyDwTFBB8BDqho4/kbEW+vamG
WFk27VIwWxLdjwZNp6FbXe8sqr7T1Jf6dCwIS/aALGU4C+C4mWjqPTRlegJCVmEC
bjjTl0pMd+Ep+le8Szy4Q/xQ7/Kt1/Vrj3XNNK5Sw1qWts5/HSNzDSvkPCk4uuN3
9zKXzohNMbo9dx8KdkJH7IC3aBEdzkxRClJnnQIDAQABAoIBAF8IKoCbbIUBRkYm
ng1tpMVEmHooLjE0I47dW64019Cs4Cjia70oOZJETG9k87V4gXHk1hXRyx3w/CNR
ZsKjFuvvLcbOjE2bLQoODtlgCbfRz88nPwJfsPmBdXNB9rDOxiCIFImqRZHkGMT3
siMP9w90jrVUoj9qgYKiKodz3LAMFLnc6QkuAPRdEEI14bxRCcc3w2nKcCbj8Yye
qKDbWVqp36kWBYcWgD2vzRcBOjJ3mRvTwflEg8HXbU88ANlGf7QQ1YhB9ueAE9Eg
E18BMoa8cjon+xH2OvH+PlOZkbCLojoFtlUSh99eApp51+DCTKwQfqeg5ufdwm5G
vyci9X0CgYEA+tFy8dqGOlmHDRUg3lW68dA1zkm15WAZoj7NvCGvTQyfoeH3Syoo
CNKJqJkGHVWksCbTnORGVLDsz+l5a2BJY3L0xiDxpciIomZO18/IGJ4K5X4tm10i
330jUMO/22BXgNzBLU8gIyQLIu45NgOugtfwFKrCvYER4m0/peXWtB8CgYEA11Sm
mC9V3mwceUuHWgqxsZpxrTQEDTAOhrGiIl5ZtoD7moMpu9MOo3qGd8W4dNbQwONq
RxDigTQWv9oxqqDTYQjoZRSo1zYYgn9K17V5v4P1pzFMVBJnK1ElciWObt9l2g4O
B/+SWQncwShHhfwJPrYmVQGgb3fETfZiiGvyTMMCgYEAxf4MtKqCBxGhMEybc6dN
OZHYx40cT4M6+P6GvZoBndr3MH0GD4mprL01+adCUmnG5V7g8RqqAjTf24g8Vuzd
Qen/G1/qIapZYYlNd8MH+5bWly6xpdExtCY+eITtsKkuqgSZYcDyZ4sOV3aiJudl
HNiFJmtd6uY2Tf1bnwP+JpUCgYA4aup3Rze1Xhgbw6lD8zdZdEDCg7VoCyZTLilv
3c6dna/ObP07Q/I67PhcW0aX/kyVrUAEPK1L8uze+Xk33oljjCTvjvkp4feMAXQH
jnnGrvlnA+iewm+bjthDzwlBjXCvMC2G9PRQNeBMD5Sly0JU1v62GQYDDps1Xg+0
9Kt4ZwKBgF8995suzG285txhAnlbKJpXB67f20s0DpBb4QdB+1PuizuyWWxPYAcu
J1h1Q5Z6frEwd4ye/bcpReEScPXOKEB+1b3TWGCWNC2jhfChtZSH1Y3Z3mL0SfwT
n9txBjxLOx1G83OQYY3J6Bnwkn5/whXGdMlfOR963adQNweQuatB
-----END RSA PRIVATE KEY-----`

//   - Generate new private key using openssl genrsa -out key.pem 2048
//   - Create a self-signed certificate for key.pem using
//     openssl req -x509 -key key.pem -out certificate.pem
//   - Create a file with the data to be encrypted using
//     echo -n "This is a test" > test.txt
//   - Generate PKCS #7 enveloped data encrypted using AES using
//     openssl cms -encrypt -in test.txt -outform pem -recip certificate.pem -aes256 -keyopt rsa_padding_mode:oaep
//   - Change the CMS header to the PKCS7 header.
var RSAOAEPSHA1EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIBwgYJKoZIhvcNAQcDoIIBszCCAa8CAQAxggFqMIIBZgIBADBOMDYxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMRIwEAYDVQQKDAlUZXN0IENlcnQC
FCoCAvxWlBvVDwodj5frshHwg0GSMA0GCSqGSIb3DQEBBzAABIIBAJk/va3ss8Rc
1hs7V7uo4XwrV+VVJMQtSnAwp2YihMtSPj3hiS6ZbhoadrK5tGersZZLiz25Wr9u
qMc5D6EpCeo6dr4Fy4JJvBb6dox1X5jzA4G2m1gKv+J+KthWLBEuBKKYYeVIayr4
qiqyPW1re0yEREMapXfBHdzcYAHCa+sSomkYpMAHCqHd04uk8lznIE8mt/p3dJQx
QqFtYQ1YHeXFTEoVFnumVjyWwFX2fMgjSkdA34v/xDQc2HP81QMC45f5HOVbPk/Z
EmOBSvoUL9VQWKMwxS2RGDQKAZMbYOn948TI0DyairG5BQzHFC3OWUlp/DpVJoIA
c40TpDjW1bAwPAYJKoZIhvcNAQcBMB0GCWCGSAFlAwQBKgQQSHiMHMNoG+HSC12p
ym5+dYAQ4qvztP5U0tRnA7ezUef7Fg==
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIDTTCCAjWgAwIBAgIUKgIC/FaUG9UPCh2Pl+uyEfCDQZIwDQYJKoZIhvcNAQEL
BQAwNjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxEjAQBgNVBAoM
CVRlc3QgQ2VydDAeFw0yMTAyMTAxNjIwMDBaFw0yMTAzMTIxNjIwMDBaMDYxCzAJ
BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMRIwEAYDVQQKDAlUZXN0IENl
cnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDS+Nd7wSgX6j6xLCZd
SdwAq8BWlbruuFEf6VYvZ5FBzIOeTwFketD1tJie8tq9sEv8V8sFYlZruM4mA12G
jxSse5rwVTf6TomQChEuvW+l6dB4N7EQ6EtZ1bmBKUk0jhqmrHTgT8YbyBKZ/2t+
UqkcvmHIPBMUEHwEOqGjj+RsRb69qYZYWTbtUjBbEt2PBk2noVtd7yyqvtPUl/p0
LAhL9oAsZTgL4LiZaOo9NGV6AkJWYQJuONOXSkx34Sn6V7xLPLhD/FDv8q3X9WuP
dc00rlLDWpa2zn8dI3MNK+Q8KTi643f3MpfOiE0xuj13Hwp2QkfsgLdoER3OTFEK
UmedAgMBAAGjUzBRMB0GA1UdDgQWBBRaaQq4a4U1xwlriTHnfBq8X5ctvDAfBgNV
HSMEGDAWgBRaaQq4a4U1xwlriTHnfBq8X5ctvDAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4IBAQDFURgxrMBCmMVZFR9+jlCAK9T/tH3tX4d2iIVaj1Aj
dw0wDAO20QPM/ZHlPM+l8yMT8ACY5ZHp6neRcaz9qmNeYAeGVu5twIo30LfRWDoY
rfL3gIHeUXQCdxwJMh3z14WNdxPBoPXerw9LT1J97Dg81e/b+Za/vdRfqNIKbADj
yoP7LBNaX/r83/SsGGbtW618sar+27wWRlGeZvFq8hwh+qyj3S7wtY7wx5weR7eZ
S9K/MB9npTbIjDUidByTIhpk0hS55s1jF6U0wlmV0oUmC4wBIebyo1cL/CMPRv+a
z/D9/ZvUoaotiATRWSKLCmxapcmGbMxhHHYWYWtzPCt1
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0vjXe8EoF+o+sSwmXUncAKvAVpW67rhRH+lWL2eRQcyDnk8B
ZHrQ9bSYnvLavbBL/FfLBWJWa7jOJgNdho8UrHua8FU3+k6JkAoRLr1vpenQeDex
EOhLWdW5gSlJNI4apqx04E/GG8gSmf9rflKpHL5hyDwTFBB8BDqho4/kbEW+vamG
WFk27VIwWxLdjwZNp6FbXe8sqr7T1Jf6dCwIS/aALGU4C+C4mWjqPTRlegJCVmEC
bjjTl0pMd+Ep+le8Szy4Q/xQ7/Kt1/Vrj3XNNK5Sw1qWts5/HSNzDSvkPCk4uuN3
9zKXzohNMbo9dx8KdkJH7IC3aBEdzkxRClJnnQIDAQABAoIBAF8IKoCbbIUBRkYm
ng1tpMVEmHooLjE0I47dW64019Cs4Cjia70oOZJETG9k87V4gXHk1hXRyx3w/CNR
ZsKjFuvvLcbOjE2bLQoODtlgCbfRz88nPwJfsPmBdXNB9rDOxiCIFImqRZHkGMT3
siMP9w90jrVUoj9qgYKiKodz3LAMFLnc6QkuAPRdEEI14bxRCcc3w2nKcCbj8Yye
qKDbWVqp36kWBYcWgD2vzRcBOjJ3mRvTwflEg8HXbU88ANlGf7QQ1YhB9ueAE9Eg
E18BMoa8cjon+xH2OvH+PlOZkbCLojoFtlUSh99eApp51+DCTKwQfqeg5ufdwm5G
vyci9X0CgYEA+tFy8dqGOlmHDRUg3lW68dA1zkm15WAZoj7NvCGvTQyfoeH3Syoo
CNKJqJkGHVWksCbTnORGVLDsz+l5a2BJY3L0xiDxpciIomZO18/IGJ4K5X4tm10i
330jUMO/22BXgNzBLU8gIyQLIu45NgOugtfwFKrCvYER4m0/peXWtB8CgYEA11Sm
mC9V3mwceUuHWgqxsZpxrTQEDTAOhrGiIl5ZtoD7moMpu9MOo3qGd8W4dNbQwONq
RxDigTQWv9oxqqDTYQjoZRSo1zYYgn9K17V5v4P1pzFMVBJnK1ElciWObt9l2g4O
B/+SWQncwShHhfwJPrYmVQGgb3fETfZiiGvyTMMCgYEAxf4MtKqCBxGhMEybc6dN
OZHYx40cT4M6+P6GvZoBndr3MH0GD4mprL01+adCUmnG5V7g8RqqAjTf24g8Vuzd
Qen/G1/qIapZYYlNd8MH+5bWly6xpdExtCY+eITtsKkuqgSZYcDyZ4sOV3aiJudl
HNiFJmtd6uY2Tf1bnwP+JpUCgYA4aup3Rze1Xhgbw6lD8zdZdEDCg7VoCyZTLilv
3c6dna/ObP07Q/I67PhcW0aX/kyVrUAEPK1L8uze+Xk33oljjCTvjvkp4feMAXQH
jnnGrvlnA+iewm+bjthDzwlBjXCvMC2G9PRQNeBMD5Sly0JU1v62GQYDDps1Xg+0
9Kt4ZwKBgF8995suzG285txhAnlbKJpXB67f20s0DpBb4QdB+1PuizuyWWxPYAcu
J1h1Q5Z6frEwd4ye/bcpReEScPXOKEB+1b3TWGCWNC2jhfChtZSH1Y3Z3mL0SfwT
n9txBjxLOx1G83OQYY3J6Bnwkn5/whXGdMlfOR963adQNweQuatB
-----END RSA PRIVATE KEY-----`

// RSAOAEPSHA256EncryptedTestFixture reuses the certificate and key of the signing fixtures. The
// message was made with OpenSSL 4.1, which names SHA-256 for both the OAEP hash and MGF1:
//
//	openssl cms -encrypt -in test.txt -binary -outform pem -recip cert.pem -aes256 -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256
var RSAOAEPSHA256EncryptedTestFixture = `
-----BEGIN PKCS7-----
MIIB0AYJKoZIhvcNAQcDoIIBwTCCAb0CAQAxggF4MIIBdAIBADAxMCkxEDAOBgNV
BAoTB0FjbWUgQ28xFTATBgNVBAMTDEVkZGFyZCBTdGFyawIEItzA4TA4BgkqhkiG
9w0BAQcwK6ANMAsGCWCGSAFlAwQCAaEaMBgGCSqGSIb3DQEBCDALBglghkgBZQME
AgEEggEACXHLwG4XdLm3jZY5J9OAP0PNJNKDVlsV3jbTVEXSj1XYDJt9pLffePQ4
y2IoAfhzriH/gIEk85DNz7d31qX8C/YmlGaW+dapIzfC+AB+5RfHz+Jdb7nHkeP5
+LiKWv+enCZh+78vAHOzGbMlLkTMXWPjuxMEVPnYJcsQJtF0LdwJZV2+GN89KVyy
16/ctujA2hOCB2ZvwU93/C7VL4rmbs2HHbjnj2wN44TiSnFJJkGcCPMi5ZMHVNvH
hf9AopHY2Z2KU7wX+5xm6YdxKNdn16gV8w2mLCHNKHLGJZhvvRJCzJsm6P82P6vJ
cufFeqlCLLjbIF1x2pkGpwhHhNDzrzA8BgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEq
BBAN9tto4IqmHKYa6vLt3lCsgBDYOjTBEGyQ+jhSybGK/h2m
-----END PKCS7-----
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIEItzA4TANBgkqhkiG9w0BAQsFADApMRAwDgYDVQQKEwdB
Y21lIENvMRUwEwYDVQQDEwxFZGRhcmQgU3RhcmswHhcNMjEwMjIzMTIxODQ2WhcN
MjIwMjIzMTIxODQ3WjAlMRAwDgYDVQQKEwdBY21lIENvMREwDwYDVQQDEwhKb24g
U25vdzCCAR8wDQYJKoZIhvcNAQEBBQADggEMADCCAQcCggEAcWPIQrIZColwlCsn
ZK7ULUEkZHtvMOCaLaHA4laqLuJOeQxAyWpL1m11w3GpFeBwPEdrThoG8b04xaPB
CuO9MPTvYqWqT1Eq0UWgbEjpZGmiLOjmIeBS8GaajDQVVRLYLlVEfwt+GNqUvZEa
x7OqvnBoQ2aJZFk+5xsuXkhLzwx4NBAatdYbuh5j5iN69ASJzjaiYNq3Ct1PvsJN
ZZ2w98rAmbCjqkVJrN5/yFink6l15s9lyidrdDUl8Ig5gPatBpvsNG14d5c4bVD+
DJc0vpZ8fYSuW480mwlAeUV8DAxv7jTEKguDJgOAT3HknzMgCBY3USxsvyu4G29r
4jmEbQIBA6NIMEYwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwME
MB8GA1UdIwQYMBaAFOy+qIFIokwb/0GSIt4DOBOXMd5vMA0GCSqGSIb3DQEBCwUA
A4IBAQA8F85MhBw5QxwrwRluL4waSXpxdRNpkN2K59eEqTUc+5lFLhinvX9WwkvR
ToBiRpvX50GtCWZ/r5Lx2UxTyh3vKsgjhkXcvm6pvVVfqyz5pNQv3v2Q838xM98+
15srGU9uU71McPZ5MmkmfHfgBaz5CCfUcsroJJ19pebaSARkRnb0bR36voXUbtwM
F89PLjXUYLxSaWcOpRQ1ju0Kq7K3MDqauPzzl3HtrpGkCsoHMfb5o/HYNj+Pmxfl
l3QH5xhOzVdioaGwE4SkY5Z5szZ8n+qi/Zd59PBCOpLoXvcB9WRTMmYkxmDOVcwI
pQfViIYaatHkjbS/2C/Cx0hfb/6S
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEnwIBAAKCAQBxY8hCshkKiXCUKydkrtQtQSRke28w4JotocDiVqou4k55DEDJ
akvWbXXDcakV4HA8R2tOGgbxvTjFo8EK470w9O9ipapPUSrRRaBsSOlkaaIs6OYh
4FLwZpqMNBVVEtguVUR/C34Y2pS9kRrHs6q+cGhDZolkWT7nGy5eSEvPDHg0EBq1
1hu6HmPmI3r0BInONqJg2rcK3U++wk1lnbD3ysCZsKOqRUms3n/IWKeTqXXmz2XK
J2t0NSXwiDmA9q0Gm+w0bXh3lzhtUP4MlzS+lnx9hK5bjzSbCUB5RXwMDG/uNMQq
C4MmA4BPceSfMyAIFjdRLGy/K7gbb2viOYRtAgEDAoIBAEuX2tchZgcGSw1yGkMf
OB4rbZhSSiCVvB5r1ew5xsnsNFCy1ducMo7zo9ehG2Pq9X2E8jQRWfZ+JdkX1gdC
fiCjSkHDxt+LceDZFZ2F8O2bwXNF7sFAN0rvEbLNY44MkB7jgv9c/rs8YykLZy/N
HH71mteZsO2Q1JoSHumFh99cwWHFhLxYh64qFeeH6Gqx6AM2YVBWHgs7OuKOvc8y
zUbf8xftPht1kMwwDR1XySiEYtBtn74JflK3DcT8oxOuCZBuX6sMJHKbVP41zDj+
FJZBmpAvNfCEYJUr1Hg+DpMLqLUg+D6v5vpliburbk9LxcKFZyyZ9QVe7GoqMLBu
eGsCgYEAummUj4MMKWJC2mv5rj/dt2pj2/B2HtP2RLypai4et1/Ru9nNk8cjMLzC
qXz6/RLuJ7/eD7asFS3y7EqxKxEmW0G8tTHjnzR/3wnpVipuWnwCDGU032HJVd13
LMe51GH97qLzuDZjMCz+VlbCNdSslMgWWK0XmRnN7Yqxvh6ao2kCgYEAm7fTRBhF
JtKcaJ7d8BQb9l8BNHfjayYOMq5CxoCyxa2pGBv/Mrnxv73Twp9Z/MP0ue5M5nZt
GMovpP5cGdJLQ2w5p4H3opcuWeYW9Yyru2EyCEAI/hD/Td3QVP0ukc19BDuPl5Wg
eIFs218uiVOU4pw3w+Et5B1PZ/F+ZLr5LGUCgYB8RmMKV11w7CyRnVEe1T56Ru09
Svlp4qQt0xucHr8k6ovSkTO32hd10yxw/fyot0lv1T61JHK4yUydhyDHYMQ81n3O
IUJqIv/qBpuOxvQ8UqwIQ3iU69uOk6TIhSaNlqlJwffQJEIgHf7kOdbOjchjMA7l
yLpmETPzscvUFGcXmwKBgGfP4i1lg283EvBp6Uq4EqQ/ViL6l5zECXce1y8Ady5z
xhASqiHRS9UpN9cU5qiCoyae3e75nhCGym3+6BE23Nede8UBT8G6HuaZZKOzHSeW
IVrVW1QLVN6T4DioybaI/gLSX7pjwFBWSJI/dFuNDexoJS1AyUK+NO/2VEMnUMhD
AoGAOsdn3Prnh/mjC95vraHCLap0bRBSexMdx77ImHgtFUUcSaT8DJHs+NZw1RdM
SZA0J+zVQ8q7B11jIgz5hMz+chedwoRjTL7a8VRTKHFmmBH0zlEuV7L79w6HkRCQ
VRg10GUN6heGLv0aOHbPdobcuVDH4sgOqpT1QnOuce34sQs=
-----END RSA PRIVATE KEY-----`
