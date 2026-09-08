package main

import (
	"crypto/elliptic"
	"encoding/base64"
	"strings"
	"testing"
)

func TestLoadRuntimeSecrets(t *testing.T) {
	privateKey, publicKey := testVAPIDKeyPair()

	tests := []struct {
		name            string
		jwtSecret       string
		vapidPublicKey  string
		vapidPrivateKey string
		wantErr         string
	}{
		{
			name:            "loads valid secrets",
			jwtSecret:       strings.Repeat("j", 32),
			vapidPublicKey:  publicKey,
			vapidPrivateKey: privateKey,
		},
		{
			name:            "rejects a short JWT secret",
			jwtSecret:       "too-short",
			vapidPublicKey:  publicKey,
			vapidPrivateKey: privateKey,
			wantErr:         "JWT_SECRET must contain at least 32 bytes",
		},
		{
			name:            "rejects an invalid VAPID public key",
			jwtSecret:       strings.Repeat("j", 32),
			vapidPublicKey:  "not-base64!",
			vapidPrivateKey: privateKey,
			wantErr:         "VAPID_PUBLIC_KEY is not valid URL-safe base64",
		},
		{
			name:            "rejects a mismatched VAPID key pair",
			jwtSecret:       strings.Repeat("j", 32),
			vapidPublicKey:  publicKey,
			vapidPrivateKey: base64.RawURLEncoding.EncodeToString(append(make([]byte, 31), 2)),
			wantErr:         "VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY do not match",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("JWT_SECRET", test.jwtSecret)
			t.Setenv("VAPID_PUBLIC_KEY", test.vapidPublicKey)
			t.Setenv("VAPID_PRIVATE_KEY", test.vapidPrivateKey)

			secrets, err := loadRuntimeSecrets()
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("loadRuntimeSecrets() error = %v, want error containing %q", err, test.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("loadRuntimeSecrets() error = %v", err)
			}
			if string(secrets.jwtKey) != test.jwtSecret {
				t.Fatal("loadRuntimeSecrets() did not preserve JWT_SECRET")
			}
			if secrets.vapidPublicKey != test.vapidPublicKey {
				t.Fatal("loadRuntimeSecrets() did not preserve VAPID_PUBLIC_KEY")
			}
			if secrets.vapidPrivateKey != test.vapidPrivateKey {
				t.Fatal("loadRuntimeSecrets() did not preserve VAPID_PRIVATE_KEY")
			}
		})
	}
}

func testVAPIDKeyPair() (privateKey, publicKey string) {
	privateBytes := append(make([]byte, 31), 1)
	publicX, publicY := elliptic.P256().ScalarBaseMult(privateBytes)
	publicBytes := elliptic.Marshal(elliptic.P256(), publicX, publicY)

	return base64.RawURLEncoding.EncodeToString(privateBytes),
		base64.RawURLEncoding.EncodeToString(publicBytes)
}
