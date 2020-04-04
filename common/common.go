package common

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
)

func AsJsonPretty(obj interface{}) []byte {
	s, _ := json.MarshalIndent(obj, "", "  ")
	return s
}

type Logger func(mask string, argv ...interface{}) (int, error)

func NewLogger(id string) Logger {
	return func(mask string, argv ...interface{}) (int, error) {
		msg := fmt.Sprintf(mask, argv...)
		lines := strings.Split(msg, "\n")
		for i := range lines {
			fmt.Printf("%s: %s\n", id, lines[i])
		}
		return 0, nil
	}
}

func VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	roots := x509.NewCertPool()
	for _, rawCert := range rawCerts {
		c, _ := x509.ParseCertificate(rawCert)

		roots.AddCert(c)
	}
	cert, _ := x509.ParseCertificate(rawCerts[0])
	opts := x509.VerifyOptions{
		DNSName: cert.Subject.CommonName,
		Roots:   roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: " + err.Error())
	}
	return nil
}
