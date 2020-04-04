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

type Logger struct {
	Info  func(mask string, argv ...interface{}) (int, error)
	Debug func(mask string, argv ...interface{}) (int, error)
	Error func(mask string, argv ...interface{}) (int, error)
}

func NewLogger(id string) Logger {
	logFunc := func(level string, mask string, argv ...interface{}) (int, error) {
		msg := fmt.Sprintf(mask, argv...)
		lines := strings.Split(msg, "\n")
		for i := range lines {
			fmt.Printf("%s:%s: %s\n", level, id, lines[i])
		}
		return 0, nil
	}
	return Logger{
		Info: func(mask string, argv ...interface{}) (int, error) {
			return logFunc("INFO", mask, argv...)
		},
		Debug: func(mask string, argv ...interface{}) (int, error) {
			return logFunc("DEBUG", mask, argv...)
		},
		Error: func(mask string, argv ...interface{}) (int, error) {
			return logFunc("ERROR", mask, argv...)
		},
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
