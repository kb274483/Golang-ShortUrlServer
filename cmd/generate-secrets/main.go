package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	webpush "github.com/SherClockHolmes/webpush-go"
)

func main() {
	jwtBytes := make([]byte, 48)
	if _, err := rand.Read(jwtBytes); err != nil {
		log.Fatalf("generate JWT secret: %v", err)
	}

	vapidPrivateKey, vapidPublicKey, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		log.Fatalf("generate VAPID keys: %v", err)
	}

	fmt.Printf("JWT_SECRET=%s\n", base64.RawURLEncoding.EncodeToString(jwtBytes))
	fmt.Printf("VAPID_PUBLIC_KEY=%s\n", vapidPublicKey)
	fmt.Printf("VAPID_PRIVATE_KEY=%s\n", vapidPrivateKey)
}
