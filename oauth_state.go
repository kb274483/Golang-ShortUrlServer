package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

const googleStateCookie = "shorturl_oauth_state"
const googleStateLifetime = 10 * time.Minute

func googleStateSigningKey() []byte {
	mac := hmac.New(sha256.New, JWTKey)
	_, _ = mac.Write([]byte("shorturl-google-oauth-state-v1"))
	return mac.Sum(nil)
}

func issueGoogleState(c *gin.Context) (string, error) {
	nonce, err := generateRandomString(32)
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := jwt.StandardClaims{
		Audience: "google-oauth-state", Subject: nonce,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(googleStateLifetime).Unix(),
	}
	state, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(googleStateSigningKey())
	if err != nil {
		return "", err
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(googleStateCookie, state, int(googleStateLifetime.Seconds()), "/url_api", "", strings.HasPrefix(appConfig.GoogleRedirectURL, "https://"), true)
	return state, nil
}

func validateGoogleState(c *gin.Context) error {
	state := c.Query("state")
	cookie, err := c.Cookie(googleStateCookie)
	if err != nil || state == "" || !hmac.Equal([]byte(state), []byte(cookie)) {
		return errors.New("OAuth state does not match the browser cookie")
	}
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(state, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected OAuth signing method")
		}
		return googleStateSigningKey(), nil
	})
	if err != nil || !token.Valid || claims.Audience != "google-oauth-state" || claims.Subject == "" || claims.ExpiresAt <= time.Now().Unix() {
		return errors.New("invalid or expired OAuth state")
	}
	return nil
}

func clearGoogleStateCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(googleStateCookie, "", -1, "/url_api", "", strings.HasPrefix(appConfig.GoogleRedirectURL, "https://"), true)
}
