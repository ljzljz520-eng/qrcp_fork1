package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	id, err := Generate("127.0.0.1")
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if len(id.Public) != 32 {
		t.Fatalf("unexpected Ed25519 public key size: %d", len(id.Public))
	}
	if len(id.PublicKeyFingerprint) != 64 {
		t.Fatalf("public key fingerprint should be 64 hex chars, got %d", len(id.PublicKeyFingerprint))
	}
	if len(id.CertFingerprint) != 64 {
		t.Fatalf("cert fingerprint should be 64 hex chars, got %d", len(id.CertFingerprint))
	}
	cert, err := x509.ParseCertificate(id.CertDER)
	if err != nil {
		t.Fatalf("parsing generated certificate: %v", err)
	}
	// The SPKI hash of the certificate's public key must match the identity
	// fingerprint, because the Ed25519 identity key is the certificate key.
	spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spkiDER)
	if got := hex.EncodeToString(sum[:]); got != id.PublicKeyFingerprint {
		t.Fatalf("certificate public key fingerprint = %s, want %s", got, id.PublicKeyFingerprint)
	}
	certSum := sha256.Sum256(id.CertDER)
	if got := hex.EncodeToString(certSum[:]); got != id.CertFingerprint {
		t.Fatalf("cert fingerprint mismatch")
	}
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		t.Fatal("certificate is not valid now")
	}
}

func TestShortFingerprint(t *testing.T) {
	got := ShortFingerprint("0123456789abcdef0000")
	want := "01:23:45:67:89:AB:CD:EF"
	if got != want {
		t.Fatalf("ShortFingerprint() = %q, want %q", got, want)
	}
}

func TestTLSHandshakePresentsIdentityCertificate(t *testing.T) {
	id, err := Generate("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{id.Certificate}, MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	defer ts.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var presentedSPKI string
	client.Transport.(*http.Transport).TLSClientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		c, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		spkiDER, err := x509.MarshalPKIXPublicKey(c.PublicKey)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(spkiDER)
		presentedSPKI = hex.EncodeToString(sum[:])
		return nil
	}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("TLS request error: %v", err)
	}
	defer resp.Body.Close()
	if presentedSPKI != id.PublicKeyFingerprint {
		t.Fatalf("TLS peer presented fingerprint %s, want %s", presentedSPKI, id.PublicKeyFingerprint)
	}
	// The generated cert must be usable for a TLS 1.3 handshake.
	state := resp.TLS
	if state == nil {
		t.Fatal("missing TLS connection state")
	}
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("Ed25519 cert should negotiate TLS 1.3, got %x", state.Version)
	}
}
