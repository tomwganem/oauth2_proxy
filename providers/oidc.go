package providers

import (
	"context"
	"fmt"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
)

type OIDCProvider struct {
	*ProviderData

	Verifier *oidc.IDTokenVerifier
}

func NewOIDCProvider(p *ProviderData) *OIDCProvider {
	p.ProviderName = "OpenID Connect"
	return &OIDCProvider{ProviderData: p}
}

func (p *OIDCProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}

	rawAcessToken, ok := token.Extra("access_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an access_token")
	}

	var email string
	email, err = emailFromAccessToken(rawAcessToken)
	if err != nil {
		return
	}

	s = &SessionState{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresOn:    token.Expiry,
		Email:        email,
	}

	return
}

func emailFromAccessToken(accessToken string) (string, error) {

	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(accessToken, ".")
	jwtData := strings.TrimSuffix(jwt[1], "=")
	b, err := base64.RawURLEncoding.DecodeString(jwtData)
	if err != nil {
		return "", err
	}

	var email struct {
		Email         string `json:"email"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("missing email")
	}
	return email.Email, nil
}

func (p *OIDCProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn
	s.ExpiresOn = time.Now().Add(time.Second).Truncate(time.Second)
	fmt.Printf("refreshed access token %s (expired on %s)\n", s, origExpiration)
	return false, nil
}
