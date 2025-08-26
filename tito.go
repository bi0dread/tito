package tito

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"math"
	"time"
)

func GenerateTOTP(secret string, timestamp time.Time, digits int) (string, error) {
	// Decode the base32 secret
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %v", err)
	}

	// Calculate the counter value (timestamp / time step)
	timeStep := int64(30) // 30 seconds is the default time step
	counter := uint64(timestamp.Unix() / timeStep)

	// Convert the counter to a byte array
	counterBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter = counter >> 8
	}

	// Generate the HMAC-SHA1 hash
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(counterBytes)
	hash := hmacSha1.Sum(nil)

	// Truncate the hash to get the OTP
	offset := hash[len(hash)-1] & 0xf
	binary := ((int(hash[offset]) & 0x7f) << 24) |
		((int(hash[offset+1]) & 0xff) << 16) |
		((int(hash[offset+2]) & 0xff) << 8) |
		(int(hash[offset+3]) & 0xff)

	// Generate the OTP code with the specified number of digits
	otp := binary % int(math.Pow10(digits))
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, otp), nil
}

func ValidateTOTP(secret, userCode string, timestamp time.Time, digits int, timeWindow int) bool {
	timeStep := int64(30) // 30 seconds is the default time step

	// Check the OTP for the current, previous, and next time steps
	for i := -timeWindow; i <= timeWindow; i++ {
		// Calculate the time for the current step
		stepTime := timestamp.Add(time.Duration(i) * time.Second * time.Duration(timeStep))

		// Generate the TOTP code for the current step
		code, err := GenerateTOTP(secret, stepTime, digits)
		if err != nil {
			continue
		}

		// Compare the generated code with the user-provided code
		if code == userCode {
			return true
		}
	}

	return false
}

// GenerateSecretFromSeed generates a Base32-encoded secret from a seed string.
func GenerateSecretFromSeed(seed string) string {
	length := 32

	// Hash the seed using SHA-256
	hash := sha256.Sum256([]byte(seed))

	// Encode the hash in Base32
	secret := base32.StdEncoding.EncodeToString(hash[:])

	// Trim padding characters ('=') for cleaner output
	secret = trimPadding(secret)

	// Ensure the secret is of the desired length
	if len(secret) > length {
		secret = secret[:length]
	}

	return secret
}

// trimPadding removes padding characters ('=') from the Base32 string.
func trimPadding(s string) string {
	return string(bytes.TrimRight([]byte(s), "="))
}
