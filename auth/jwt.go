package auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	//"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"strings"
	"time"
)

type IssuerName string

type Issuer struct {
	Name       IssuerName
	Alg        string
	publickey  interface{}
	privatekey interface{}
}

type VerifiedClaims struct {
	Email      string              `json:"email,omitempty"`       // Common primary email identity
	Issuer     IssuerName          `json:"iss"`                   // Used to look up trusted issuer
	ExpiresAt  int64               `json:"exp"`                   // When this claim expires
	Picture    string              `json:"picture,omitempty"`     // URL pointing to a user picture
	Name       string              `json:"name,omitempty"`        // Full name
	GivenName  string              `json:"given_name,omitempty"`  // given_name
	FamilyName string              `json:"family_name,omitempty"` // family_name
	Values     map[string][]string `json:"values,omitempty"`      // Like LDAP groups
}

type Trust struct {
	Issuers    map[IssuerName]*Issuer
	IssuerName IssuerName
}

func (t *Trust) TrustIssuers(pemCerts []byte) ([]*Issuer, error) {
	issuers := make([]*Issuer, 0)
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		issuer, err := t.TrustIssuer(block.Bytes, nil)
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, issuer)
	}

	return issuers, nil
}

// Use iss with Name "" to make a default issuer
func (t *Trust) TrustIssuer(cert []byte, priv interface{}) (*Issuer, error) {
	if t.Issuers == nil {
		t.Issuers = make(map[IssuerName]*Issuer)
	}
	pubcert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	name := IssuerName(pubcert.Subject.String())
	if t.Issuers[name] == nil {
		t.Issuers[name] = &Issuer{}
	}
	t.Issuers[name].Name = name
	switch k := pubcert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		t.Issuers[name].publickey = k
		t.Issuers[name].Alg = "ES256"
	case *rsa.PublicKey:
		t.Issuers[name].publickey = k
		t.Issuers[name].Alg = "RSA512"
	default:
		return nil, fmt.Errorf("Unrecognized public key type")
	}
	if priv != nil {
		t.IssuerName = name
		switch k := priv.(type) {
		case *ecdsa.PrivateKey:
			t.Issuers[name].privatekey = k
		case *rsa.PrivateKey:
			t.Issuers[name].privatekey = k
		default:
			return nil, fmt.Errorf("Unrecognized private key type")
		}
	}
	// Parse PEM files for signing and trust keys
	return t.Issuers[name], nil
}

func (vc *VerifiedClaims) CheckExpiration() error {
	now := time.Now().Unix()
	if now < vc.ExpiresAt {
		return fmt.Errorf("JWT expired %d sec ago", (now - vc.ExpiresAt))
	}
	return nil
}

func GetJWT(s string, issuer *Issuer) (string, error) {
	var claims jwt.MapClaims
	err := json.Unmarshal([]byte(s), &claims)
	if err != nil {
		return "", err
	}
	// TODO: only recognize the alg that signer actually HAS
	alg := jwt.GetSigningMethod(issuer.Alg)
	if alg == nil {
		return "", fmt.Errorf("could not find %s algorithm", issuer.Alg)
	}
	token := jwt.NewWithClaims(alg, claims)

	tokenStr, err := token.SignedString(issuer.privatekey)
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func authenticate(issuer *Issuer, token string) (jwt.Claims, error) {
	js, err := jwt.Parse(token, func(jt *jwt.Token) (interface{}, error) {
		if jt == nil {
			return nil, fmt.Errorf("invalid token")
		}
		// Only recognize alg that signer actually HAS
		if jt.Method != jwt.GetSigningMethod(issuer.Alg) {
			return nil, fmt.Errorf("We ONLY support %s tokens", issuer.Alg)
		}
		return issuer.publickey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error checking token: %v", err)
	}
	return js.Claims, nil
}

func Encode(vc VerifiedClaims, trust *Trust) (string, error) {
	duration := time.Duration(8) * 60 * time.Minute
	return EncodeWithDuration(vc, duration, trust)
}

func EncodeWithDuration(vc VerifiedClaims, duration time.Duration, trust *Trust) (string, error) {
	// Find the trust
	if len(vc.Issuer) == 0 {
		vc.Issuer = trust.IssuerName
	}
	iss := trust.Issuers[vc.Issuer]

	// We need private key (identity) to sign
	if iss.privatekey == nil {
		return "", fmt.Errorf("We trust %s, but are not signers", iss.Name)
	}
	// Make a JWT
	now := time.Now()
	vc.ExpiresAt = now.Add(duration).Unix()
	b, err := json.Marshal(vc)
	if err != nil {
		return "", err
	}
	return GetJWT(string(b), iss)
}

func tryDecode(s string, trust *Trust) (interface{}, error) {
	// If the first one does not work, then walk the array for more
	for k := range trust.Issuers {
		iss := trust.Issuers[k]
		return authenticate(iss, s)
	}
	return nil, fmt.Errorf("issuer not found")
}

func Decode(b []byte, trust *Trust) (VerifiedClaims, error) {
	var vc VerifiedClaims
	// Decode, but defer returning an error until we parse the input
	if b == nil || len(b) == 0 {
		return vc, fmt.Errorf("empty claims")
	}
	// Does it smply not decode and claims marshal to json?
	p, decodeErr := tryDecode(strings.TrimSpace(string(b)), trust)
	if decodeErr != nil {
		return vc, decodeErr
	}
	if p == nil {
		return vc, fmt.Errorf("no claims in jwt token came back")
	}
	bytes, err := json.Marshal(p)
	if err != nil {
		return vc, err
	}
	err = json.Unmarshal(bytes, &vc)
	if err != nil {
		return vc, err
	}
	decodeErr = vc.CheckExpiration()
	return vc, decodeErr
}
