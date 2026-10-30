package pkcs7

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// resign replaces the signed attributes of the first signer and signs their encoding in the given
// order, the way a signer that does not sort its SET OF would.
func resign(t *testing.T, sd *SignedData, key crypto.Signer, attrs []attribute) {
	t.Helper()
	si := &sd.sd.SignerInfos[0]
	si.AuthenticatedAttributes = attrs
	encoded, err := encodeSignedAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	h := crypto.SHA256.New()
	h.Write(encoded)
	if si.EncryptedDigest, err = key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256); err != nil {
		t.Fatal(err)
	}
}

// signedFixture signs content with a fresh RSA test certificate and returns the builder before
// Finish, so tests can alter the signer.
func signedFixture(t *testing.T, config SignerInfoConfig) (*SignedData, certKeyPair) {
	t.Helper()
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := NewSignedData([]byte("signed content"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSigner(cert.Certificate, cert.PrivateKey, config); err != nil {
		t.Fatal(err)
	}
	return sd, cert
}

// finishAndParse marshals the builder and parses the result again.
func finishAndParse(t *testing.T, sd *SignedData) *PKCS7 {
	t.Helper()
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	return p7
}

// TestVerifyUnsortedSignedAttributes checks that a signature over signed attributes in the order
// the signer wrote them verifies, even when that order is not the DER order.
func TestVerifyUnsortedSignedAttributes(t *testing.T) {
	t.Parallel()
	sd, cert := signedFixture(t, SignerInfoConfig{})
	attrs := slices.Clone(sd.sd.SignerInfos[0].AuthenticatedAttributes)
	slices.Reverse(attrs)
	resign(t, sd, cert.PrivateKey, attrs)
	if err := finishAndParse(t, sd).Verify(VerifyOptions{}); err != nil {
		t.Fatalf("Verify of unsorted signed attributes: %v", err)
	}
}

// TestVerifySignedAttributeRules checks the RFC 5652 rules for the content-type and
// message-digest attributes.
func TestVerifySignedAttributeRules(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		edit    func(attrs []attribute) []attribute
		wantErr string
	}{
		{
			name: "content type does not match",
			edit: func(attrs []attribute) []attribute {
				for i := range attrs {
					if attrs[i].Type.Equal(OIDAttributeContentType) {
						value, _ := asn1.Marshal(OIDSignedData)
						attrs[i].Value = asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: value}
					}
				}
				return attrs
			},
			wantErr: "content-type",
		},
		{
			name: "content type missing",
			edit: func(attrs []attribute) []attribute {
				return slices.DeleteFunc(attrs, func(a attribute) bool { return a.Type.Equal(OIDAttributeContentType) })
			},
			wantErr: "content-type",
		},
		{
			name: "message digest twice",
			edit: func(attrs []attribute) []attribute {
				for _, a := range attrs {
					if a.Type.Equal(OIDAttributeMessageDigest) {
						return append(attrs, a)
					}
				}
				return attrs
			},
			wantErr: "more than once",
		},
		{
			name: "message digest with two values",
			edit: func(attrs []attribute) []attribute {
				for i := range attrs {
					if attrs[i].Type.Equal(OIDAttributeMessageDigest) {
						v := attrs[i].Value.Bytes
						attrs[i].Value = asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Bytes: append(slices.Clone(v), v...)}
					}
				}
				return attrs
			},
			wantErr: "more than one value",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sd, cert := signedFixture(t, SignerInfoConfig{})
			attrs := tt.edit(slices.Clone(sd.sd.SignerInfos[0].AuthenticatedAttributes))
			resign(t, sd, cert.PrivateKey, attrs)
			err := finishAndParse(t, sd).Verify(VerifyOptions{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Verify error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestVerifySignerCertificates checks that a message without its signer certificate verifies
// against a certificate the caller supplies.
func TestVerifySignerCertificates(t *testing.T) {
	t.Parallel()
	sd, cert := signedFixture(t, SignerInfoConfig{})
	sd.certs = nil
	p7 := finishAndParse(t, sd)
	if err := p7.Verify(VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "no certificate for signer") {
		t.Fatalf("Verify without the signer certificate: error = %v", err)
	}
	if err := p7.Verify(VerifyOptions{SignerCertificates: []*x509.Certificate{cert.Certificate}}); err != nil {
		t.Fatalf("Verify with SignerCertificates: %v", err)
	}
}

// TestVerifyChainTime checks that chains are checked at the current time unless the caller asks for
// the signing time, so a backdated signing-time attribute cannot revive an expired signer.
func TestVerifyChainTime(t *testing.T) {
	t.Parallel()
	now := time.Now()
	rootKey, err := testKeyFor(x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PKCS7 Test Root CA"},
		NotBefore:             now.Add(-3 * time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	key, err := testKeyFor(x509.ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "expired signer"},
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, rootCert, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := NewSignedData([]byte("backdated"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSigner(signer, key, SignerInfoConfig{SigningTime: now.Add(-90 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	p7 := finishAndParse(t, sd)
	if err := p7.Verify(VerifyOptions{Roots: roots}); err == nil {
		t.Error("an expired signer verified at the current time")
	}
	if err := p7.Verify(VerifyOptions{Roots: roots, VerifyAtSigningTime: true}); err != nil {
		t.Errorf("Verify at the signing time: %v", err)
	}
	if err := p7.Verify(VerifyOptions{Roots: roots, CurrentTime: now.Add(-100 * time.Minute)}); err != nil {
		t.Errorf("Verify at an explicit time: %v", err)
	}
}

// TestVerifyRSAPSSFromOpenSSL verifies RSASSA-PSS signatures that OpenSSL produced.
func TestVerifyRSAPSSFromOpenSSL(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	cert, err := createTestCertificate(x509.SHA256WithRSA)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"cert.pem":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate.Raw}),
		"key.pem":     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"content.txt": []byte("signed with RSASSA-PSS"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		digest string
		salt   string
	}{
		{"sha256", "digest"},
		{"sha384", "digest"},
		{"sha256", "20"},
	} {
		t.Run(tt.digest+"/salt="+tt.salt, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "signed.der")
			cmd := exec.CommandContext(t.Context(), "openssl", "cms", "-sign", "-binary", "-nodetach", "-md", tt.digest,
				"-in", filepath.Join(dir, "content.txt"), "-signer", filepath.Join(dir, "cert.pem"), "-inkey", filepath.Join(dir, "key.pem"),
				"-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:"+tt.salt, "-outform", "DER", "-out", out)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("openssl cms -sign failed with %s: %s", err, output)
			}
			der, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(der)
			if err != nil {
				t.Fatal(err)
			}
			if alg := p7.Signers[0].DigestEncryptionAlgorithm.Algorithm; !alg.Equal(OIDEncryptionAlgorithmRSASSAPSS) {
				t.Fatalf("OpenSSL used signature algorithm %v, want RSASSA-PSS", alg)
			}
			if err := p7.Verify(VerifyOptions{}); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestPSSParameters checks RSASSA-PSS parameter decoding.
func TestPSSParameters(t *testing.T) {
	t.Parallel()
	sha256ID := pkix.AlgorithmIdentifier{Algorithm: OIDDigestAlgorithmSHA256}
	mgf := func(hash asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
		params, err := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: hash})
		if err != nil {
			t.Fatal(err)
		}
		return pkix.AlgorithmIdentifier{Algorithm: OIDMaskGenerationFunctionMGF1, Parameters: asn1.RawValue{FullBytes: params}}
	}
	encode := func(p pssParameters) asn1.RawValue {
		der, err := asn1.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return asn1.RawValue{FullBytes: der}
	}
	if salt, err := pssSaltLength(encode(pssParameters{Hash: sha256ID, MGF: mgf(OIDDigestAlgorithmSHA256), SaltLength: 32, TrailerField: 1}), crypto.SHA256); err != nil || salt != 32 {
		t.Errorf("SHA-256 parameters: salt %d, error %v", salt, err)
	}
	if _, err := pssSaltLength(encode(pssParameters{Hash: sha256ID, MGF: mgf(OIDDigestAlgorithmSHA1), SaltLength: 32, TrailerField: 1}), crypto.SHA256); err == nil {
		t.Error("an MGF1 hash that differs from the digest was accepted")
	}
	if _, err := pssSaltLength(encode(pssParameters{Hash: sha256ID, MGF: mgf(OIDDigestAlgorithmSHA256), SaltLength: 32, TrailerField: 1}), crypto.SHA512); err == nil {
		t.Error("a parameter hash that differs from the signer digest was accepted")
	}
	if _, err := pssSaltLength(asn1.RawValue{}, crypto.SHA256); err == nil {
		t.Error("RSASSA-PSS without parameters was accepted")
	}
}
