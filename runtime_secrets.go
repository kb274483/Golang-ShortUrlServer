package main

import (
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
)

const minimumJWTSecretBytes = 32

type runtimeSecrets struct {
	jwtKey          []byte
	vapidPublicKey  string
	vapidPrivateKey string
}

func loadRuntimeSecrets() (runtimeSecrets, error) {
	jwtSecret := os.Getenv("JWT_SECRET")
	if len([]byte(jwtSecret)) < minimumJWTSecretBytes {
		return runtimeSecrets{}, fmt.Errorf("JWT_SECRET must contain at least %d bytes", minimumJWTSecretBytes)
	}

	vapidPublicKey := strings.TrimSpace(os.Getenv("VAPID_PUBLIC_KEY"))
	vapidPrivateKey := strings.TrimSpace(os.Getenv("VAPID_PRIVATE_KEY"))
	if err := validateVAPIDKeyPair(vapidPublicKey, vapidPrivateKey); err != nil {
		return runtimeSecrets{}, err
	}

	return runtimeSecrets{
		jwtKey:          []byte(jwtSecret),
		vapidPublicKey:  vapidPublicKey,
		vapidPrivateKey: vapidPrivateKey,
	}, nil
}

func validateVAPIDKeyPair(publicKey, privateKey string) error {
	publicBytes, err := decodeVAPIDKey("VAPID_PUBLIC_KEY", publicKey)
	if err != nil {
		return err
	}
	privateBytes, err := decodeVAPIDKey("VAPID_PRIVATE_KEY", privateKey)
	if err != nil {
		return err
	}

	curve := elliptic.P256()
	publicX, publicY := elliptic.Unmarshal(curve, publicBytes)
	if publicX == nil || publicY == nil {
		return errors.New("VAPID_PUBLIC_KEY is not a valid P-256 public key")
	}

	privateScalar := new(big.Int).SetBytes(privateBytes)
	if privateScalar.Sign() <= 0 || privateScalar.Cmp(curve.Params().N) >= 0 {
		return errors.New("VAPID_PRIVATE_KEY is not a valid P-256 private key")
	}

	expectedX, expectedY := curve.ScalarBaseMult(privateBytes)
	if expectedX.Cmp(publicX) != 0 || expectedY.Cmp(publicY) != 0 {
		return errors.New("VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY do not match")
	}

	return nil
}

func decodeVAPIDKey(name, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is required", name)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	decoded, err = base64.URLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid URL-safe base64", name)
	}
	return decoded, nil
}
