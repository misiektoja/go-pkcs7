package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// allContentAlgorithms accepts every content cipher, including single DES.
var allContentAlgorithms = DecryptOptions{ContentEncryptionAlgorithms: []ContentEncryptionAlgorithm{AES128CBC, AES192CBC, AES256CBC, DESEDE3CBC, DESCBC}}

// TestEncrypt round-trips EnvelopedData through every content cipher and key transport.
func TestEncrypt(t *testing.T) {
	t.Parallel()
	keyEncryptions := []EncryptOptions{
		{KeyEncryption: RSAPKCS1v15},
		{KeyEncryption: RSAOAEP, OAEPHash: crypto.SHA1},
		{KeyEncryption: RSAOAEP},
		{KeyEncryption: RSAOAEP, OAEPHash: crypto.SHA512},
	}
	for _, keyAlg := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.SHA512WithRSA} {
		cert, err := createTestCertificate(keyAlg)
		if err != nil {
			t.Fatal(err)
		}
		for _, alg := range allContentAlgorithms.ContentEncryptionAlgorithms {
			for _, opts := range keyEncryptions {
				opts.ContentEncryption = alg
				t.Run(keyAlg.String()+"/"+alg.String()+"/"+opts.KeyEncryption.String(), func(t *testing.T) {
					plaintext := []byte("Hello Secret World!")
					encrypted, err := Encrypt(plaintext, []*x509.Certificate{cert.Certificate}, opts)
					if err != nil {
						t.Fatal(err)
					}
					p7, err := Parse(encrypted)
					if err != nil {
						t.Fatalf("cannot Parse encrypted result: %s", err)
					}
					if got, err := p7.ContentEncryptionAlgorithm(); err != nil || got != alg {
						t.Errorf("ContentEncryptionAlgorithm() = %v, %v, want %v", got, err, alg)
					}
					result, err := p7.Decrypt(cert.Certificate, cert.PrivateKey.(crypto.Decrypter), allContentAlgorithms)
					if err != nil {
						t.Fatalf("cannot Decrypt encrypted result: %s", err)
					}
					if !bytes.Equal(plaintext, result) {
						t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
					}
				})
			}
		}
	}
}

// TestEncryptDefaults checks that zero options select AES-128-CBC and PKCS #1 v1.5 key transport.
func TestEncryptDefaults(t *testing.T) {
	t.Parallel()
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt([]byte("defaults"), []*x509.Certificate{cert.Certificate}, EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	ed := p7.raw.(envelopedData)
	if alg := ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm; !alg.Equal(OIDEncryptionAlgorithmAES128CBC) {
		t.Errorf("content encryption algorithm = %v, want AES-128-CBC", alg)
	}
	if alg := ed.RecipientInfos[0].KeyEncryptionAlgorithm.Algorithm; !alg.Equal(OIDEncryptionAlgorithmRSA) {
		t.Errorf("key encryption algorithm = %v, want rsaEncryption", alg)
	}
}

// TestEncryptRejectsBadInput covers recipients and options that Encrypt cannot use.
func TestEncryptRejectsBadInput(t *testing.T) {
	t.Parallel()
	rsaCert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	ecCert, err := createTestCertificate(x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	recipients := []*x509.Certificate{rsaCert.Certificate}
	for _, tt := range []struct {
		name       string
		recipients []*x509.Certificate
		opts       EncryptOptions
		want       error
	}{
		{"no recipients", nil, EncryptOptions{}, nil},
		{"ECDSA recipient", []*x509.Certificate{ecCert.Certificate}, EncryptOptions{}, ErrUnsupportedKeyType},
		{"unknown content cipher", recipients, EncryptOptions{ContentEncryption: 99}, ErrUnsupportedEncryptionAlgorithm},
		{"unknown key transport", recipients, EncryptOptions{KeyEncryption: 99}, ErrUnsupportedKeyEncryptionAlgorithm},
		{"MD5 OAEP hash", recipients, EncryptOptions{KeyEncryption: RSAOAEP, OAEPHash: crypto.MD5}, ErrUnsupportedKeyEncryptionHash},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Encrypt([]byte("x"), tt.recipients, tt.opts)
			if err == nil || (tt.want != nil && !errors.Is(err, tt.want)) {
				t.Errorf("Encrypt error = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestEncryptUsingPSK round-trips EncryptedData through every content cipher.
func TestEncryptUsingPSK(t *testing.T) {
	t.Parallel()
	for alg, c := range contentCiphers {
		t.Run(alg.String(), func(t *testing.T) {
			plaintext := []byte("Hello Secret World!")
			key := bytes.Repeat([]byte{0x5a}, c.keyLen)
			ciphertext, err := EncryptUsingPSK(plaintext, key, EncryptOptions{ContentEncryption: alg})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			result, err := p7.DecryptUsingPSK(key, allContentAlgorithms)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		})
	}
}

// TestEncryptUsingPSKKeyLength checks that a missing key or a key of the wrong length is refused.
func TestEncryptUsingPSKKeyLength(t *testing.T) {
	t.Parallel()
	if _, err := EncryptUsingPSK([]byte("x"), nil, EncryptOptions{}); !errors.Is(err, ErrPSKNotProvided) {
		t.Errorf("nil key: error = %v, want ErrPSKNotProvided", err)
	}
	if _, err := EncryptUsingPSK([]byte("x"), make([]byte, 8), EncryptOptions{ContentEncryption: AES256CBC}); err == nil {
		t.Error("an 8-byte key for AES-256-CBC was accepted")
	}
}

// TestPad checks PKCS #7 padding and that the input slice is left untouched.
func TestPad(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Original  []byte
		Expected  []byte
		BlockSize int
	}{
		{[]byte{0x1, 0x2, 0x3, 0x10}, []byte{0x1, 0x2, 0x3, 0x10, 0x4, 0x4, 0x4, 0x4}, 8},
		{[]byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, []byte{0x1, 0x2, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8}, 8},
	}
	for _, test := range tests {
		padded, err := pad(test.Original, test.BlockSize)
		if err != nil {
			t.Errorf("pad encountered error: %s", err)
			continue
		}
		if !bytes.Equal(test.Expected, padded) {
			t.Errorf("pad results mismatch:\n\tExpected: %X\n\tActual: %X", test.Expected, padded)
		}
	}
	backing := make([]byte, 4, 16)
	if _, err := pad(backing, 8); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backing[:8], make([]byte, 8)) {
		t.Errorf("pad wrote into the spare capacity of its input: % X", backing[:8])
	}
}

// TestOAEPParametersRoundTrip checks that the encoded RSAES-OAEP parameters name the OAEP hash for
// both the digest and MGF1, as crypto/rsa uses one hash for both.
func TestOAEPParametersRoundTrip(t *testing.T) {
	t.Parallel()
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		alg, err := EncryptOptions{KeyEncryption: RSAOAEP, OAEPHash: hash}.keyEncryptionAlgorithm()
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseOAEPParameters(alg.Parameters)
		if err != nil {
			t.Fatalf("%v: %v", hash, err)
		}
		want := &rsa.OAEPOptions{Hash: hash, MGFHash: hash}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%v: parameters decode to %+v, want %+v", hash, got, want)
		}
	}
}

// Test_marshalEncryptedContent checks the implicit [0] wrapper around the ciphertext.
func Test_marshalEncryptedContent(t *testing.T) {
	t.Parallel()
	content := []byte{}
	got := marshalEncryptedContent(content)

	expected := asn1.RawValue{Class: 2, Tag: 0, IsCompound: false, Bytes: []byte{}, FullBytes: nil}
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("marshalEncryptedContent() = %v, want %v", got, expected)
	}

	content = []byte{34, 165, 121, 103, 15, 109, 119, 147, 39, 236, 212, 103, 143, 164, 172, 22}
	got = marshalEncryptedContent(content)
	expected = asn1.RawValue{Class: 2, Tag: 0, IsCompound: false, Bytes: []byte{34, 165, 121, 103, 15, 109, 119, 147, 39, 236, 212, 103, 143, 164, 172, 22}, FullBytes: nil}
	if !reflect.DeepEqual(expected, got) {
		t.Errorf("marshalEncryptedContent() = %v, want %v", got, expected)
	}
}

// TestEncryptAndDecryptWithOpenSSL checks that OpenSSL decrypts what Encrypt produces.
func TestEncryptAndDecryptWithOpenSSL(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	tf := UnmarshalTestFixture(RSAOAEPSHA256EncryptedTestFixture) // use existing fixture with cert + key
	recipientFile := filepath.Join(t.TempDir(), "recipient.pem")
	privateKey, err := x509.MarshalPKCS8PrivateKey(tf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	recipientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tf.Certificate.Raw})
	recipientPEM = append(recipientPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})...)
	if err := os.WriteFile(recipientFile, recipientPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, opts := range []EncryptOptions{
		{ContentEncryption: AES256CBC},
		{ContentEncryption: AES128CBC, KeyEncryption: RSAOAEP},
		{ContentEncryption: DESEDE3CBC, KeyEncryption: RSAOAEP, OAEPHash: crypto.SHA512},
	} {
		t.Run(opts.ContentEncryption.String()+"/"+opts.KeyEncryption.String(), func(t *testing.T) {
			content := []byte("this is the content")
			encryptedContent, err := Encrypt(content, []*x509.Certificate{tf.Certificate}, opts)
			if err != nil {
				t.Fatal(err)
			}
			contentFile := filepath.Join(t.TempDir(), "content.pem")
			if err := os.WriteFile(contentFile, pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: encryptedContent}), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.CommandContext(t.Context(), "openssl", "cms", "-decrypt", "-inform", "pem", "-in", contentFile, "-recip", recipientFile).CombinedOutput()
			if err != nil {
				t.Fatalf("openssl command failed with %s: %s", err, out)
			}
			if !bytes.Equal(content, out) {
				t.Errorf("openssl decrypted %q, want %q", out, content)
			}
		})
	}
}

// TestDecryptOpenSSLOAEPParameters checks RSAES-OAEP recipients whose MGF1 hash differs from the
// OAEP hash and that carry a label, as openssl cms writes them.
func TestDecryptOpenSSLOAEPParameters(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	tf := UnmarshalTestFixture(RSAOAEPSHA256EncryptedTestFixture)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "recipient.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tf.Certificate.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	content := []byte("this is the content")
	contentFile := filepath.Join(dir, "content.txt")
	if err := os.WriteFile(contentFile, content, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name    string
		oaepMD  string
		mgf1MD  string
		hasMGF1 bool
	}{
		// SHA-1 is the MGF1 default, so OpenSSL leaves the MGF1 parameters out.
		{name: "SHA256/MGF1-SHA1", oaepMD: "sha256", mgf1MD: "sha1"},
		{name: "SHA256/MGF1-SHA512", oaepMD: "sha256", mgf1MD: "sha512", hasMGF1: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			encryptedFile := filepath.Join(t.TempDir(), "encrypted.der")
			out, err := exec.CommandContext(t.Context(), "openssl", "cms", "-encrypt", "-binary", "-aes128",
				"-in", contentFile, "-outform", "DER", "-out", encryptedFile, "-recip", certFile,
				"-keyopt", "rsa_padding_mode:oaep",
				"-keyopt", "rsa_oaep_md:"+tt.oaepMD,
				"-keyopt", "rsa_mgf1_md:"+tt.mgf1MD,
				"-keyopt", "rsa_oaep_label:0102030405",
			).CombinedOutput()
			if err != nil {
				t.Fatalf("openssl command failed with %s: %s", err, out)
			}
			der, err := os.ReadFile(encryptedFile)
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			params := p7.raw.(envelopedData).RecipientInfos[0].KeyEncryptionAlgorithm.Parameters.FullBytes
			var p rsaOAEPParameters
			if _, err := asn1.Unmarshal(params, &p); err != nil {
				t.Fatal(err)
			}
			if len(p.PSource.Algorithm) == 0 {
				t.Fatal("openssl wrote no OAEP label")
			}
			if got := len(p.MGF.Algorithm) != 0; got != tt.hasMGF1 {
				t.Fatalf("MGF1 parameters present = %v, want %v", got, tt.hasMGF1)
			}
			got, err := p7.Decrypt(tf.Certificate, tf.PrivateKey, DecryptOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, content) {
				t.Errorf("decrypted %q, want %q", got, content)
			}
		})
	}
}

// TestEncryptUsingPSKWithOpenSSL checks EncryptedData in both directions against openssl cms
// -EncryptedData_encrypt and -EncryptedData_decrypt.
func TestEncryptUsingPSKWithOpenSSL(t *testing.T) {
	t.Parallel()
	requireOpenSSL(t)
	for _, tt := range []struct {
		alg  ContentEncryptionAlgorithm
		flag string
	}{
		{AES128CBC, "-aes128"},
		{AES192CBC, "-aes192"},
		{AES256CBC, "-aes256"},
		{DESEDE3CBC, "-des3"},
	} {
		t.Run(tt.alg.String(), func(t *testing.T) {
			key := make([]byte, contentCiphers[tt.alg].keyLen)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}
			content := []byte("this is the content")
			dir := t.TempDir()
			contentFile := filepath.Join(dir, "content.txt")
			if err := os.WriteFile(contentFile, content, 0o600); err != nil {
				t.Fatal(err)
			}

			encrypted, err := EncryptUsingPSK(content, key, EncryptOptions{ContentEncryption: tt.alg})
			if err != nil {
				t.Fatal(err)
			}
			encryptedFile := filepath.Join(dir, "library.der")
			if err := os.WriteFile(encryptedFile, encrypted, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), "openssl", "cms", "-EncryptedData_decrypt", "-inform", "DER", "-in", encryptedFile, "-secretkey", hex.EncodeToString(key))
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("openssl cms -EncryptedData_decrypt failed with %s: %s", err, stderr.Bytes())
			}
			if !bytes.Equal(out, content) {
				t.Errorf("openssl decrypted %q, want %q", out, content)
			}

			opensslFile := filepath.Join(dir, "openssl.der")
			if out, err := exec.CommandContext(t.Context(), "openssl", "cms", "-EncryptedData_encrypt", "-binary", "-in", contentFile, "-outform", "DER", "-out", opensslFile, tt.flag, "-secretkey", hex.EncodeToString(key)).CombinedOutput(); err != nil {
				t.Fatalf("openssl cms -EncryptedData_encrypt failed with %s: %s", err, out)
			}
			der, err := os.ReadFile(opensslFile)
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := p7.DecryptUsingPSK(key, DecryptOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, content) {
				t.Errorf("DecryptUsingPSK returned %q, want %q", plaintext, content)
			}
		})
	}
}
