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
	Assert func(condition bool, message string)
	Info   func(mask string, argv ...interface{}) (int, error)
	Debug  func(mask string, argv ...interface{}) (int, error)
	Error  func(mask string, argv ...interface{}) (int, error)
	State  string
	Id     string
}

func NewLogger(id string) Logger {
	return initLogger(Logger{Id: id})
}

func (logger Logger) Push(state string) Logger {
	logger.State = fmt.Sprintf("%s/%s", logger.State, state)
	return logger
}

func initLogger(logger Logger) Logger {
	logFunc := func(level string, mask string, argv ...interface{}) (int, error) {
		msg := fmt.Sprintf(mask, argv...)
		lines := strings.Split(msg, "\n")
		for i := range lines {
			fmt.Printf("%s|%s|%s: %s\n", logger.Id, level, logger.State, lines[i])
		}
		return 0, nil
	}

	logger.Assert = func(condition bool, message string) {
		if condition == false {
			panic(message)
		}
	}
	logger.Info = func(mask string, argv ...interface{}) (int, error) {
		return logFunc("INFO", mask, argv...)
	}
	logger.Debug = func(mask string, argv ...interface{}) (int, error) {
		return logFunc("DEBUG", mask, argv...)
	}
	logger.Error = func(mask string, argv ...interface{}) (int, error) {
		return logFunc("ERROR", mask, argv...)
	}
	return logger
}

func VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	roots := x509.NewCertPool()
	for _, rawCert := range rawCerts {
		c, _ := x509.ParseCertificate(rawCert)

		roots.AddCert(c)
	}
	if rawCerts == nil || len(rawCerts) == 0 {
		return fmt.Errorf("no certificate to verify")
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

func AppendToStringSet(strs []string, str string) []string {
	for _, s := range strs {
		if s == str {
			return strs
		}
	}
	return append(strs, str)
}
