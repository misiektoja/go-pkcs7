package pkcs7_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"slices"
	"time"

	"github.com/misiektoja/go-pkcs7"
)

// The examples below are included in the documentation site between the --8<-- markers. The
// helpers create throwaway keys and certificates, which real code loads from storage or an HSM.

// exampleCA is a self-signed CA that issues the example certificates.
type exampleCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// newExampleCA creates a CA with a new ECDSA P-256 key, valid from 30 days ago to 30 days ahead.
func newExampleCA(name string) exampleCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := exampleTemplate(name, time.Now().AddDate(0, 0, -30), time.Now().AddDate(0, 0, 30))
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return exampleCA{cert: exampleCreate(template, template, key.Public(), key), key: key}
}

// issue creates a certificate for key signed by the CA and valid for one day.
func (ca exampleCA) issue(name string, key crypto.Signer) *x509.Certificate {
	return ca.issueValid(name, key, time.Now().Add(-time.Minute), time.Now().Add(24*time.Hour))
}

// issueValid creates a certificate for key signed by the CA with the given validity.
func (ca exampleCA) issueValid(name string, key crypto.Signer, notBefore, notAfter time.Time) *x509.Certificate {
	template := exampleTemplate(name, notBefore, notAfter)
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	return exampleCreate(template, ca.cert, key.Public(), ca.key)
}

// intermediate creates a subordinate CA with a new ECDSA P-256 key and the validity of its issuer.
func (ca exampleCA) intermediate(name string) exampleCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := exampleTemplate(name, ca.cert.NotBefore, ca.cert.NotAfter)
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	return exampleCA{cert: exampleCreate(template, ca.cert, key.Public(), ca.key), key: key}
}

// exampleTemplate returns a certificate template with a random serial number.
func exampleTemplate(name string, notBefore, notAfter time.Time) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		log.Fatal(err)
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
}

// exampleCreate signs template with parentKey and parses the result.
func exampleCreate(template, parent *x509.Certificate, pub crypto.PublicKey, parentKey crypto.Signer) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

// newECDSAKey returns a new ECDSA P-256 key.
func newECDSAKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

// newRSAKey returns a new 2048-bit RSA key.
func newRSAKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

// Example_signAndVerify signs content with a certificate issued by a CA and verifies the result
// against that CA.
func Example_signAndVerify() {
	ca := newExampleCA("Example CA")
	key := newECDSAKey()
	cert := ca.issue("Example signer", key)
	caCert := ca.cert

	// --8<-- [start:sign]
	sd, err := pkcs7.NewSignedData([]byte("hello, CMS"))
	if err != nil {
		log.Fatal(err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		log.Fatal(err)
	}
	signed, err := sd.Finish()
	if err != nil {
		log.Fatal(err)
	}
	// --8<-- [end:sign]

	// --8<-- [start:verify]
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if err := p7.Verify(pkcs7.VerifyOptions{Roots: roots}); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", p7.Content)
	// --8<-- [end:verify]

	// Output: hello, CMS
}

// ExampleSignedData_AddSignerChain sends the intermediate CA certificate with the signature, so a
// verifier needs only the root.
func ExampleSignedData_AddSignerChain() {
	root := newExampleCA("Example root")
	intermediate := root.intermediate("Example intermediate")
	key := newECDSAKey()
	cert := intermediate.issue("Example signer", key)
	intermediateCert, rootCert := intermediate.cert, root.cert

	// --8<-- [start:chain]
	sd, err := pkcs7.NewSignedData([]byte("signed through an intermediate"))
	if err != nil {
		log.Fatal(err)
	}
	parents := []*x509.Certificate{intermediateCert}
	if err := sd.AddSignerChain(cert, key, parents, pkcs7.SignerInfoConfig{}); err != nil {
		log.Fatal(err)
	}
	signed, err := sd.Finish()
	if err != nil {
		log.Fatal(err)
	}

	p7, err := pkcs7.Parse(signed)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	if err := p7.Verify(pkcs7.VerifyOptions{Roots: roots}); err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(p7.Certificates), "certificates in the message")
	// --8<-- [end:chain]

	// Output: 2 certificates in the message
}

// ExampleSignedData_Detach creates a detached signature and verifies it with the content supplied
// separately.
func ExampleSignedData_Detach() {
	ca := newExampleCA("Example CA")
	key := newECDSAKey()
	cert := ca.issue("Example signer", key)

	// --8<-- [start:detached]
	content := []byte("content sent next to the signature")
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		log.Fatal(err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		log.Fatal(err)
	}
	sd.Detach()
	signature, err := sd.Finish()
	if err != nil {
		log.Fatal(err)
	}

	p7, err := pkcs7.Parse(signature)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("content in the message:", len(p7.Content))
	p7.Content = content
	if err := p7.Verify(pkcs7.VerifyOptions{}); err != nil {
		log.Fatal(err)
	}
	fmt.Println("detached signature verified")
	// --8<-- [end:detached]

	// Output:
	// content in the message: 0
	// detached signature verified
}

// ExampleSignedData_RemoveCertificates leaves the signer certificate out of the message. The
// verifier already holds it.
func ExampleSignedData_RemoveCertificates() {
	ca := newExampleCA("Example CA")
	key := newECDSAKey()
	cert := ca.issue("Example signer", key)

	// --8<-- [start:without-certificates]
	sd, err := pkcs7.NewSignedData([]byte("no certificates attached"))
	if err != nil {
		log.Fatal(err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		log.Fatal(err)
	}
	sd.RemoveCertificates()
	signed, err := sd.Finish()
	if err != nil {
		log.Fatal(err)
	}

	p7, err := pkcs7.Parse(signed)
	if err != nil {
		log.Fatal(err)
	}
	opts := pkcs7.VerifyOptions{SignerCertificates: []*x509.Certificate{cert}}
	if err := p7.Verify(opts); err != nil {
		log.Fatal(err)
	}
	fmt.Println("verified with a known signer certificate")
	// --8<-- [end:without-certificates]

	// Output: verified with a known signer certificate
}

// ExamplePKCS7_UnmarshalSignedAttribute adds a signed attribute and reads it back after
// verification.
func ExamplePKCS7_UnmarshalSignedAttribute() {
	ca := newExampleCA("Example CA")
	key := newECDSAKey()
	cert := ca.issue("Example signer", key)

	// --8<-- [start:attributes]
	// An attribute type from a private arc. Use the OID your protocol defines.
	oidTransactionID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

	sd, err := pkcs7.NewSignedData([]byte("content"))
	if err != nil {
		log.Fatal(err)
	}
	config := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{Type: oidTransactionID, Value: "transaction-42"},
		},
	}
	if err := sd.AddSigner(cert, key, config); err != nil {
		log.Fatal(err)
	}
	signed, err := sd.Finish()
	if err != nil {
		log.Fatal(err)
	}

	p7, err := pkcs7.Parse(signed)
	if err != nil {
		log.Fatal(err)
	}
	if err := p7.Verify(pkcs7.VerifyOptions{}); err != nil {
		log.Fatal(err)
	}
	var transactionID string
	if err := p7.UnmarshalSignedAttribute(oidTransactionID, &transactionID); err != nil {
		log.Fatal(err)
	}
	fmt.Println(transactionID)
	// --8<-- [end:attributes]

	// Output: transaction-42
}

// ExampleEncrypt encrypts content for an RSA recipient and decrypts it with the recipient key.
func ExampleEncrypt() {
	ca := newExampleCA("Example CA")
	recipientKey := newRSAKey()
	recipientCert := ca.issue("Example recipient", recipientKey)

	// --8<-- [start:encrypt]
	enveloped, err := pkcs7.Encrypt([]byte("for the recipient only"), []*x509.Certificate{recipientCert}, pkcs7.EncryptOptions{
		ContentEncryption: pkcs7.AES256CBC,
		KeyEncryption:     pkcs7.RSAOAEP,
	})
	if err != nil {
		log.Fatal(err)
	}
	// --8<-- [end:encrypt]

	// --8<-- [start:decrypt]
	p7, err := pkcs7.Parse(enveloped)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := p7.Decrypt(recipientCert, recipientKey, pkcs7.DecryptOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", plaintext)
	// --8<-- [end:decrypt]

	// Output: for the recipient only
}

// ExamplePKCS7_Recipients picks the key that can decrypt a message from several candidates.
func ExamplePKCS7_Recipients() {
	ca := newExampleCA("Example CA")
	currentKey, nextKey := newRSAKey(), newRSAKey()
	currentCert := ca.issue("Current key", currentKey)
	nextCert := ca.issue("Next key", nextKey)
	enveloped, err := pkcs7.Encrypt([]byte("rollover"), []*x509.Certificate{nextCert}, pkcs7.EncryptOptions{})
	if err != nil {
		log.Fatal(err)
	}

	// --8<-- [start:recipients]
	type candidate struct {
		cert *x509.Certificate
		key  crypto.Decrypter
	}
	candidates := []candidate{{currentCert, currentKey}, {nextCert, nextKey}}

	p7, err := pkcs7.Parse(enveloped)
	if err != nil {
		log.Fatal(err)
	}
	recipients, err := p7.Recipients()
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range recipients {
		for _, c := range candidates {
			if bytes.Equal(r.Issuer, c.cert.RawIssuer) && r.SerialNumber.Cmp(c.cert.SerialNumber) == 0 {
				plaintext, err := p7.Decrypt(c.cert, c.key, pkcs7.DecryptOptions{})
				if err != nil {
					log.Fatal(err)
				}
				fmt.Printf("%s with %s\n", plaintext, c.cert.Subject.CommonName)
			}
		}
	}
	// --8<-- [end:recipients]

	// Output: rollover with Next key
}

// ExampleEncryptUsingPSK encrypts content with a pre-shared AES-256 key.
func ExampleEncryptUsingPSK() {
	// --8<-- [start:psk]
	key := make([]byte, 32) // AES256CBC needs a 32-byte key
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	opts := pkcs7.EncryptOptions{ContentEncryption: pkcs7.AES256CBC}
	encrypted, err := pkcs7.EncryptUsingPSK([]byte("shared secret content"), key, opts)
	if err != nil {
		log.Fatal(err)
	}

	p7, err := pkcs7.Parse(encrypted)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := p7.DecryptUsingPSK(key, pkcs7.DecryptOptions{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", plaintext)
	// --8<-- [end:psk]

	// Output: shared secret content
}

// ExampleDegenerateCertificate bundles a certificate chain without a signature, the form of a
// .p7b file.
func ExampleDegenerateCertificate() {
	root := newExampleCA("Example root")
	intermediate := root.intermediate("Example intermediate")
	leaf := intermediate.issue("Example leaf", newECDSAKey())

	// --8<-- [start:degenerate]
	var chain []byte
	for _, cert := range []*x509.Certificate{leaf, intermediate.cert} {
		chain = append(chain, cert.Raw...)
	}
	bundle, err := pkcs7.DegenerateCertificate(chain)
	if err != nil {
		log.Fatal(err)
	}

	p7, err := pkcs7.Parse(bundle)
	if err != nil {
		log.Fatal(err)
	}
	for _, cert := range p7.Certificates {
		fmt.Println(cert.Subject.CommonName)
	}
	// --8<-- [end:degenerate]

	// Output:
	// Example leaf
	// Example intermediate
}

// ExampleVerifyOptions verifies an archived signature whose signer certificate has expired since
// it was made.
func ExampleVerifyOptions() {
	ca := newExampleCA("Example CA")
	key := newECDSAKey()
	now := time.Now()
	cert := ca.issueValid("Expired signer", key, now.AddDate(0, 0, -10), now.AddDate(0, 0, -5))
	sd, err := pkcs7.NewSignedData([]byte("archived document"))
	if err != nil {
		log.Fatal(err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{SigningTime: now.AddDate(0, 0, -7)}); err != nil {
		log.Fatal(err)
	}
	signed, err := sd.Finish()
	if err != nil {
		log.Fatal(err)
	}
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	// --8<-- [start:signing-time]
	if err := p7.Verify(pkcs7.VerifyOptions{Roots: roots}); err != nil {
		var invalid x509.CertificateInvalidError
		fmt.Println("expired now:", errors.As(err, &invalid) && invalid.Reason == x509.Expired)
	}
	opts := pkcs7.VerifyOptions{Roots: roots, VerifyAtSigningTime: true}
	if err := p7.Verify(opts); err != nil {
		log.Fatal(err)
	}
	fmt.Println("verified at the signing time")
	// --8<-- [end:signing-time]

	// Output:
	// expired now: true
	// verified at the signing time
}

// ExamplePKCS7_ContentEncryptionAlgorithm answers a request with the content cipher the requester
// chose.
func ExamplePKCS7_ContentEncryptionAlgorithm() {
	ca := newExampleCA("Example CA")
	serverKey := newRSAKey()
	serverCert := ca.issue("Example server", serverKey)
	clientCert := ca.issue("Example client", newRSAKey())
	request, err := pkcs7.Encrypt([]byte("request"), []*x509.Certificate{serverCert}, pkcs7.EncryptOptions{ContentEncryption: pkcs7.AES256CBC})
	if err != nil {
		log.Fatal(err)
	}

	// --8<-- [start:reply-cipher]
	p7, err := pkcs7.Parse(request)
	if err != nil {
		log.Fatal(err)
	}
	alg, err := p7.ContentEncryptionAlgorithm()
	if err != nil {
		log.Fatal(err)
	}
	reply, err := pkcs7.Encrypt([]byte("reply"), []*x509.Certificate{clientCert}, pkcs7.EncryptOptions{ContentEncryption: alg})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("reply encrypted with", alg)
	// --8<-- [end:reply-cipher]

	_ = reply
	// Output: reply encrypted with AES-256-CBC
}

// ExampleDecryptOptions accepts single DES from an old peer in addition to the default ciphers.
func ExampleDecryptOptions() {
	ca := newExampleCA("Example CA")
	key := newRSAKey()
	cert := ca.issue("Example recipient", key)
	enveloped, err := pkcs7.Encrypt([]byte("from a legacy client"), []*x509.Certificate{cert}, pkcs7.EncryptOptions{ContentEncryption: pkcs7.DESCBC})
	if err != nil {
		log.Fatal(err)
	}
	p7, err := pkcs7.Parse(enveloped)
	if err != nil {
		log.Fatal(err)
	}

	// --8<-- [start:legacy-ciphers]
	_, err = p7.Decrypt(cert, key, pkcs7.DecryptOptions{})
	fmt.Println("refused by default:", errors.Is(err, pkcs7.ErrContentEncryptionNotAllowed))

	opts := pkcs7.DecryptOptions{
		ContentEncryptionAlgorithms: append(slices.Clone(pkcs7.DefaultContentDecryptionAlgorithms), pkcs7.DESCBC),
	}
	plaintext, err := p7.Decrypt(cert, key, opts)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", plaintext)
	// --8<-- [end:legacy-ciphers]

	// Output:
	// refused by default: true
	// from a legacy client
}

// ExampleParse reads a PEM encoded message, the form OpenSSL writes with -outform PEM.
func ExampleParse() {
	ca := newExampleCA("Example CA")
	bundle, err := pkcs7.DegenerateCertificate(ca.cert.Raw)
	if err != nil {
		log.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: bundle})

	// --8<-- [start:parse-pem]
	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatal("no PEM block found")
	}
	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(p7.Certificates), "certificate and", len(p7.Signers), "signers")
	// --8<-- [end:parse-pem]

	// Output: 1 certificate and 0 signers
}

// ExampleParseWithOptions reads a message whose certificate marks the authority key identifier
// critical, as some Windows SCEP clients send.
func ExampleParseWithOptions() {
	key := newECDSAKey()
	template := exampleTemplate("Windows SCEP client", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	aki, err := asn1.Marshal(struct {
		KeyID []byte `asn1:"optional,tag:0"`
	}{KeyID: []byte{1, 2, 3, 4}})
	if err != nil {
		log.Fatal(err)
	}
	template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Critical: true, Value: aki}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		log.Fatal(err)
	}
	request, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		log.Fatal(err)
	}

	// --8<-- [start:legacy-parser]
	if _, err := pkcs7.Parse(request); err != nil {
		fmt.Println(err)
	}
	p7, err := pkcs7.ParseWithOptions(request, pkcs7.ParseOptions{LegacyCertificateParser: true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(p7.Certificates[0].Subject.CommonName)
	// --8<-- [end:legacy-parser]

	// Output:
	// x509: authority key identifier incorrectly marked critical
	// Windows SCEP client
}

// ExampleDegenerateCRL publishes a CRL in a SignedData message without signers and checks its
// signature after parsing, which Parse does not do.
func ExampleDegenerateCRL() {
	ca := newExampleCA("Example CA")
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}, ca.cert, ca.key)
	if err != nil {
		log.Fatal(err)
	}
	caCert := ca.cert

	// --8<-- [start:crl]
	message, err := pkcs7.DegenerateCRL(crlDER)
	if err != nil {
		log.Fatal(err)
	}

	p7, err := pkcs7.Parse(message)
	if err != nil {
		log.Fatal(err)
	}
	raw, err := asn1.Marshal(p7.CRLs[0])
	if err != nil {
		log.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(raw)
	if err != nil {
		log.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		log.Fatal(err)
	}
	fmt.Println("CRL number", crl.Number)
	// --8<-- [end:crl]

	// Output: CRL number 1
}
