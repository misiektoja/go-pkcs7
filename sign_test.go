package pkcs7

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestSignDefaultDigest checks that a new SignedData signs with SHA-256 unless told otherwise.
func TestSignDefaultDigest(t *testing.T) {
	t.Parallel()
	cert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, x509.ECDSAWithSHA256, true)
	if err != nil {
		t.Fatalf("failed cannot generate root cert: %v", err)
	}
	truststore := x509.NewCertPool()
	truststore.AddCert(cert.Certificate)

	toBeSigned, err := NewSignedData([]byte("test"))
	if err != nil {
		t.Fatalf("failed creating signed data: %v", err)
	}
	if err := toBeSigned.AddSignerChain(cert.Certificate, cert.PrivateKey, nil, SignerInfoConfig{}); err != nil {
		t.Fatalf("failed adding signer chain: %v", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("failed signing data: %v", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("failed parsing signed data: %v", err)
	}
	if err := p7.Verify(VerifyOptions{Roots: truststore}); err != nil {
		t.Fatalf("failed verifying PKCS7: %v", err)
	}
	if !bytes.Equal([]byte("test"), p7.Content) {
		t.Fatal("parsed PKCS7 content does not equal signed content")
	}
	if got := p7.Signers[0].DigestAlgorithm.Algorithm; !got.Equal(OIDDigestAlgorithmSHA256) {
		t.Fatalf("expected digest algorithm %q, but got %q", OIDDigestAlgorithmSHA256, got)
	}
}

// TestSign signs with every supported key type and digest through a root and intermediate chain,
// attached and detached, and verifies the result.
func TestSign(t *testing.T) {
	t.Parallel()
	content := []byte("Hello World")
	caKeys := []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.ECDSAWithSHA384}
	signerKeys := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	digests := []asn1.ObjectIdentifier{OIDDigestAlgorithmSHA1, OIDDigestAlgorithmSHA256, OIDDigestAlgorithmSHA512}
	for _, rootKey := range caKeys {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, rootKey, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", rootKey, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, interKey := range caKeys {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, interKey, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", rootKey, interKey, err)
			}
			parents := []*x509.Certificate{interCert.Certificate}
			for _, signerKey := range signerKeys {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, signerKey, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", rootKey, interKey, signerKey, err)
				}
				for _, digest := range digests {
					for _, testDetach := range []bool{false, true} {
						name := fmt.Sprintf("%s/%s/%s/%v/detached=%t", rootKey, interKey, signerKey, digest, testDetach)
						toBeSigned, err := NewSignedData(content)
						if err != nil {
							t.Fatalf("test %s: cannot initialize signed data: %s", name, err)
						}
						toBeSigned.SetDigestAlgorithm(digest)
						if err := toBeSigned.AddSignerChain(signerCert.Certificate, signerCert.PrivateKey, parents, SignerInfoConfig{}); err != nil {
							t.Fatalf("test %s: cannot add signer: %s", name, err)
						}
						if testDetach {
							toBeSigned.Detach()
						}
						signed, err := toBeSigned.Finish()
						if err != nil {
							t.Fatalf("test %s: cannot finish signing data: %s", name, err)
						}
						p7, err := Parse(signed)
						if err != nil {
							t.Fatalf("test %s: cannot parse signed data: %s", name, err)
						}
						if testDetach {
							p7.Content = content
						}
						if !bytes.Equal(content, p7.Content) {
							t.Errorf("test %s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", name, content, p7.Content)
						}
						if err := p7.Verify(VerifyOptions{Roots: truststore}); err != nil {
							t.Errorf("test %s: cannot verify signed data: %s", name, err)
						}
						if !digest.Equal(p7.Signers[0].DigestAlgorithm.Algorithm) {
							t.Errorf("test %s: expected digest algorithm %q but got %q", name, digest, p7.Signers[0].DigestAlgorithm.Algorithm)
						}
					}
				}
			}
		}
	}
}

// TestSignMD5 checks that MD5 signing needs an explicit digest choice and that Verify refuses MD5
// unless the caller allows it.
func TestSignMD5(t *testing.T) {
	t.Parallel()
	rsaCert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned, err := NewSignedData([]byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmMD5)
	if err := toBeSigned.AddSigner(rsaCert.Certificate, rsaCert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := p7.Verify(VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "MD5") {
		t.Errorf("Verify without AllowMD5: error = %v, want an MD5 refusal", err)
	}
	if err := p7.Verify(VerifyOptions{AllowMD5: true}); err != nil {
		t.Errorf("Verify with AllowMD5: %v", err)
	}

	ecCert, err := createTestCertificate(x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned, err = NewSignedData([]byte("legacy"))
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned.SetDigestAlgorithm(OIDDigestAlgorithmMD5)
	if err := toBeSigned.AddSigner(ecCert.Certificate, ecCert.PrivateKey, SignerInfoConfig{}); err == nil {
		t.Error("ECDSA with MD5 was accepted")
	}
}

// TestSetEncryptionAlgorithm checks the signature algorithm identifiers a caller may choose.
func TestSetEncryptionAlgorithm(t *testing.T) {
	t.Parallel()
	rsaCert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned, err := NewSignedData([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned.SetEncryptionAlgorithm(OIDEncryptionAlgorithmRSA)
	if err := toBeSigned.AddSigner(rsaCert.Certificate, rsaCert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if got := p7.Signers[0].DigestEncryptionAlgorithm.Algorithm; !got.Equal(OIDEncryptionAlgorithmRSA) {
		t.Errorf("signature algorithm = %v, want rsaEncryption", got)
	}
	if err := p7.Verify(VerifyOptions{}); err != nil {
		t.Errorf("Verify: %v", err)
	}

	toBeSigned, err = NewSignedData([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	toBeSigned.SetEncryptionAlgorithm(OIDEncryptionAlgorithmRSASHA512)
	if err := toBeSigned.AddSigner(rsaCert.Certificate, rsaCert.PrivateKey, SignerInfoConfig{}); err == nil {
		t.Error("sha512WithRSAEncryption was accepted with the SHA-256 digest")
	}
}

// TestSigningTime checks that a configured signing time is written to the signing-time attribute.
func TestSigningTime(t *testing.T) {
	t.Parallel()
	cert, err := createTestCertificate(x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Now().Add(-time.Minute).Truncate(time.Second).UTC()
	toBeSigned, err := NewSignedData([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{SigningTime: want}); err != nil {
		t.Fatal(err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	var got time.Time
	if err := p7.UnmarshalSignedAttribute(OIDAttributeSigningTime, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Errorf("signing time = %v, want %v", got, want)
	}
}

// ExampleSignedData shows how to produce a detached signature.
func ExampleSignedData() {
	// generate a signing cert or load a key pair
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		fmt.Printf("Cannot create test certificates: %s", err)
	}

	// Initialize a SignedData struct with content to be signed
	signedData, err := NewSignedData([]byte("Example data to be signed"))
	if err != nil {
		fmt.Printf("Cannot initialize signed data: %s", err)
	}

	// Add the signing cert and private key
	if err := signedData.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		fmt.Printf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		fmt.Printf("Cannot finish signing data: %s", err)
	}
	_ = pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature})
}

// TestUnmarshalSignedAttribute checks reading an extra signed attribute, an absent one and one
// that appears twice.
func TestUnmarshalSignedAttribute(t *testing.T) {
	t.Parallel()
	cert, err := createTestCertificate(x509.SHA512WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	oidTest := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 7}
	oidTwice := asn1.ObjectIdentifier{2, 3, 4, 5, 6, 8}
	testValue := "TestValue"
	toBeSigned, err := NewSignedData([]byte("Hello World"))
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{
		ExtraSignedAttributes: []Attribute{
			{Type: oidTest, Value: testValue},
			{Type: oidTwice, Value: "one"},
			{Type: oidTwice, Value: "two"},
		},
	}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	signed, err := toBeSigned.Finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}
	p7, err := Parse(signed)
	if err != nil {
		t.Fatalf("Cannot parse signed data: %v", err)
	}
	var actual string
	if err := p7.UnmarshalSignedAttribute(oidTest, &actual); err != nil {
		t.Fatalf("Cannot unmarshal test value: %s", err)
	}
	if testValue != actual {
		t.Errorf("Attribute does not match test value\n\tExpected: %s\n\tActual: %s", testValue, actual)
	}
	if err := p7.UnmarshalSignedAttribute(asn1.ObjectIdentifier{2, 3, 4, 5, 6, 9}, &actual); !errors.Is(err, ErrAttributeNotFound) {
		t.Errorf("absent attribute: error = %v, want ErrAttributeNotFound", err)
	}
	if err := p7.UnmarshalSignedAttribute(oidTwice, &actual); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Errorf("repeated attribute: error = %v, want a refusal", err)
	}
}

// TestDegenerateCertificate checks that OpenSSL reads a certificates-only SignedData message.
func TestDegenerateCertificate(t *testing.T) {
	t.Parallel()
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	deg, err := DegenerateCertificate(cert.Certificate.Raw)
	if err != nil {
		t.Fatal(err)
	}
	testOpenSSLParse(t, deg)
}

// testOpenSSLParse writes a DER PKCS #7 message to a file and checks that OpenSSL reads it.
func testOpenSSLParse(t *testing.T, certBytes []byte) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	certFile := filepath.Join(t.TempDir(), "certificate.p7b")
	if err := os.WriteFile(certFile, certBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), "openssl", "pkcs7", "-inform", "der", "-in", certFile).CombinedOutput(); err != nil {
		t.Fatalf("openssl pkcs7 failed with %s: %s", err, out)
	}
}

// TestDegenerateCRL checks that a GetCRL style message carries the CRL unchanged and that OpenSSL
// reads it.
func TestDegenerateCRL(t *testing.T) {
	ca, err := createTestCertificateByIssuer("CRL issuer", nil, x509.SHA256WithRSA, true)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(42), RevocationTime: time.Now().Add(-time.Minute)},
		},
	}, ca.Certificate, ca.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := DegenerateCRL(crl)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.CRLs) != 1 || len(p7.Certificates) != 0 || len(p7.Signers) != 0 {
		t.Fatalf("got %d CRLs, %d certificates and %d signers, want 1, 0 and 0", len(p7.CRLs), len(p7.Certificates), len(p7.Signers))
	}
	again, err := asn1.Marshal(p7.CRLs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, crl) {
		t.Fatal("the CRL changed on the way through the message")
	}
	testOpenSSLParse(t, der)

	if _, err := DegenerateCRL(append(slices.Clip(crl), 0)); err == nil {
		t.Fatal("DegenerateCRL accepted trailing data")
	}
	if _, err := DegenerateCRL([]byte{0x30, 0x00}); err == nil {
		t.Fatal("DegenerateCRL accepted a malformed CRL")
	}
}

// TestRemoveCertificates checks that a message without certificates verifies only with the signer
// certificate supplied by the caller.
func TestRemoveCertificates(t *testing.T) {
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := NewSignedData([]byte("content"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.RemoveCertificates()
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Certificates) != 0 {
		t.Fatalf("the message carries %d certificates", len(p7.Certificates))
	}
	if err := p7.Verify(VerifyOptions{}); err == nil {
		t.Fatal("verified without the signer certificate")
	}
	if err := p7.Verify(VerifyOptions{SignerCertificates: []*x509.Certificate{cert.Certificate}}); err != nil {
		t.Fatal(err)
	}
}
