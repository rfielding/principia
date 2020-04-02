package common

import (
	"encoding/json"
	"fmt"
	"crypto/x509"
)

func AsJsonPretty(obj interface{}) []byte {
	s, _ := json.MarshalIndent(obj, "", "  ")
	return s
}


type Logger func(mask string, argv ...interface{}) (int, error)

func NewLogger(id string) Logger {
	return func(mask string, argv ...interface{}) (int, error) {
		mask = "%s: " + mask + "\n"
		argv2 := make([]interface{}, 0)
		argv2 = append(argv2, id)
		argv2 = append(argv2, argv...)
		return fmt.Printf(mask, argv2...)
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
