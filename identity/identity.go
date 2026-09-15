// Package identity creates the ephemeral Ed25519 identity used to back
// qrcp's temporary self-signed TLS certificates.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"strings"
	"time"
)

// Identity is a one-shot Ed25519 identity and the self-signed TLS
// certificate derived from it.
type Identity struct {
	// Signer is the Ed25519 private key.
	Signer ed25519.PrivateKey
	// Public is the Ed25519 public key embedded in the certificate.
	Public ed25519.PublicKey
	// Certificate is ready to be used in a tls.Config.
	Certificate tls.Certificate
	// CertDER is the DER-encoded certificate.
	CertDER []byte
	// PublicKeyFingerprint is the hex-encoded SHA-256 of the DER-encoded
	// SubjectPublicKeyInfo. It is the digest carried by the QR code.
	PublicKeyFingerprint string
	// CertFingerprint is the hex-encoded SHA-256 of the DER-encoded
	// certificate, the same value browsers show as certificate fingerprint.
	CertFingerprint string
}

// Generate creates a new ephemeral Ed25519 identity and a self-signed TLS
// certificate valid for the given IP addresses (the bind address is usually
// passed in, when parseable).
func Generate(ipAddresses ...string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "qrcp-ephemeral",
			Organization: []string{"qrcp"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           collectIPs(ipAddresses),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, err
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	spkiSum := sha256.Sum256(spkiDER)
	certSum := sha256.Sum256(certDER)
	return &Identity{
		Signer:               priv,
		Public:               pub,
		CertDER:              certDER,
		Certificate:          tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv},
		PublicKeyFingerprint: hex.EncodeToString(spkiSum[:]),
		CertFingerprint:      hex.EncodeToString(certSum[:]),
	}, nil
}

// ShortFingerprint returns a human-friendly, grouped, short version of the
// full hex fingerprint: first 8 bytes formatted as "AB:CD:...".
func ShortFingerprint(full string) string {
	if len(full) > 16 {
		full = full[:16]
	}
	up := strings.ToUpper(full)
	groups := make([]string, 0, len(up)/2)
	for i := 0; i+2 <= len(up); i += 2 {
		groups = append(groups, up[i:i+2])
	}
	return strings.Join(groups, ":")
}

func collectIPs(values []string) []net.IP {
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, value := range values {
		// Strip a possible port / brackets.
		host := value
		if h, _, err := net.SplitHostPort(value); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if ip := net.ParseIP(host); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}
