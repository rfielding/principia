package auth

import (
	"context"
	"encoding/json"
	"fmt"
	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	//"os"
	"strings"
	"time"
)

type LinkClaims func(oidc_claims interface{}) map[string][]string

type OAuthConfig struct {
	OAUTH2_PROVIDER          string
	OAUTH2_CLIENT_ID         string
	OAUTH2_CLIENT_SECRET     string
	OAUTH2_REDIRECT_URL      string
	OAUTH2_REDIRECT_CALLBACK string
	OAUTH2_SCOPES            string
	LinkClaims               LinkClaims
}

type Authenticator struct {
	provider     *oidc.Provider
	ClientConfig oauth2.Config
	ctx          context.Context
	Trust        *Trust
	Config       *OAuthConfig
}

func NewAuthenticator(config *OAuthConfig, trust *Trust) (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, config.OAUTH2_PROVIDER)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider %s: %v", config.OAUTH2_PROVIDER, err)
	}

	clientConfig := oauth2.Config{
		ClientID:     config.OAUTH2_CLIENT_ID,
		ClientSecret: config.OAUTH2_CLIENT_SECRET,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  fmt.Sprintf("%s%s", config.OAUTH2_REDIRECT_URL, config.OAUTH2_REDIRECT_CALLBACK),
		Scopes:       strings.Split(config.OAUTH2_SCOPES, " "),
	}

	return &Authenticator{
		provider:     provider,
		ClientConfig: clientConfig,
		ctx:          ctx,
		Trust:        trust,
		Config:       config,
	}, nil
}

func (a *Authenticator) HandleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:    "id_token",
		Value:   "",
		Expires: time.Unix(0, 0),
	}
	http.SetCookie(w, &cookie)
	cookie = http.Cookie{
		Name:    "access_token",
		Value:   "",
		Expires: time.Unix(0, 0),
	}
	http.SetCookie(w, &cookie)
	cookie = http.Cookie{
		Name:    "verified_claims",
		Value:   "",
		Expires: time.Unix(0, 0),
	}
	http.SetCookie(w, &cookie)
	w.Write([]byte("logged out"))
}

func (a *Authenticator) HandleSelf(w http.ResponseWriter, r *http.Request) {
	// Dump bearer token claims
	claimsCookie, err := r.Cookie("verified_claims")
	if claimsCookie == nil {
		if err != nil {
			http.Error(w, "Failed to find verified_claims: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "No claims to return", http.StatusBadRequest)
		return
	}
	claims, err := Decode([]byte(claimsCookie.Value), a.Trust)
	j, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		http.Error(w, "failed to write claims from verified_claims!"+err.Error(), 403)
		return
	}
	w.Write(j)
}

func (a *Authenticator) HandleClaims(w http.ResponseWriter, r *http.Request) {
	// Dump bearer token claims
	idTokenCookie, err := r.Cookie("id_token")
	if idTokenCookie == nil {
		if err != nil {
			http.Error(w, "Failed to verify raw ID Token: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "No claims to return", http.StatusBadRequest)
		return
	}
	oidcConfig := &oidc.Config{
		ClientID: a.Config.OAUTH2_CLIENT_ID,
	}
	idTokenValue := idTokenCookie.Value

	rawIDToken := idTokenValue[:]
	idToken, err := a.provider.Verifier(oidcConfig).Verify(a.ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var claims interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to extract claims from id_token!"+err.Error(), 403)
		return
	}
	j, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		http.Error(w, "failed to write claims from id_token!"+err.Error(), 403)
		return
	}
	w.Write(j)
}

func (a *Authenticator) HandleOIDC(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := a.ClientConfig.Exchange(a.ctx, code)
	if err != nil {
		log.Printf("no token found: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	cookie := http.Cookie{
		Name:     "access_token",
		Value:    fmt.Sprintf("Bearer %s", token.AccessToken),
		Expires:  token.Expiry,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)

	cookie = http.Cookie{
		Name:     "id_token",
		Value:    fmt.Sprintf("%s", rawIDToken),
		Expires:  token.Expiry,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
	a.TurnIDTokenIntoCookies(w, r, rawIDToken, a.Trust)
}

// Given that we ALREADY have the rawIDToken
func (a *Authenticator) TurnIDTokenIntoCookies(
	w http.ResponseWriter,
	r *http.Request,
	rawIDToken string,
	trust *Trust,
) {
	oidcConfig := &oidc.Config{
		ClientID: a.Config.OAUTH2_CLIENT_ID,
	}

	idToken, err := a.provider.Verifier(oidcConfig).Verify(a.ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var claims interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to extract claims from id_token!"+err.Error(), 403)
		return
	}
	exp := float64(0)
	iss := ""
	picture := ""
	email := ""
	name := ""
	family_name := ""
	given_name := ""
	claimsMap, ok := claims.(map[string]interface{})
	if ok {
		claimsMapExp, ok := claimsMap["exp"].(float64)
		if ok {
			exp = claimsMapExp
		}
		claimsMapIss, ok := claimsMap["iss"].(string)
		if ok {
			iss = claimsMapIss
		}
		claimsMapPicture, ok := claimsMap["picture"].(string)
		if ok {
			picture = claimsMapPicture
		}
		claimsMapEmail, ok := claimsMap["email"].(string)
		if ok {
			email = claimsMapEmail
		}
		claimsMapName, ok := claimsMap["name"].(string)
		if ok {
			name = claimsMapName
		}
		claimsMapGivenName, ok := claimsMap["given_name"].(string)
		if ok {
			given_name = claimsMapGivenName
		}
		claimsMapFamilyName, ok := claimsMap["family_name"].(string)
		if ok {
			family_name = claimsMapFamilyName
		}
	}
	if exp == 0 {
		http.Error(w, "Token expiration is required!", 400)
		return
	}
	if len(iss) == 0 {
		http.Error(w, "Token issuer is required!", 400)
		return
	}

	// Unix time expiry of the claims
	expiry := time.Unix(int64(exp), 0)

	theClaims := make(map[string][]string)
	if a.Config.LinkClaims != nil {
		theClaims = a.Config.LinkClaims(claims)
	}
	vc, err := Encode(
		VerifiedClaims{
			Email:      email,
			Issuer:     trust.IssuerName,
			Values:     theClaims,
			Picture:    picture,
			Name:       name,
			GivenName:  given_name,
			FamilyName: family_name,
		},
		a.Trust,
	)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode claims: %v", err), http.StatusInternalServerError)
		return
	}

	// Presume that if they login with Google that they don't have a users.json entry
	// and we just issue them a JWT, as the point is to demo a Google login
	cookie := http.Cookie{
		Name:     "verified_claims",
		Value:    vc,
		Expires:  expiry,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, r.URL.Query().Get("state"), http.StatusFound)
}
