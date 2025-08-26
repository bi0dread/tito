package tito

import (
	"encoding/base32"
	"fmt"
	"strings"
	"testing"
	"time"
)

// RFC 6238 test vectors for SHA1, 8 digits, timestep 30s, T0 = 0
func TestGenerateTOTP_RFC6238Vectors_SHA1(t *testing.T) {
	secretASCII := "12345678901234567890" // 20 bytes
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secretB32 := enc.EncodeToString([]byte(secretASCII))

	tests := []struct {
		unix     int64
		expected string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}

	tt := New(Options{Digits: 8, Period: 30, Algorithm: HashSHA1})
	for _, tc := range tests {
		code, err := tt.GenerateTOTPAt(secretB32, time.Unix(tc.unix, 0).UTC())
		if err != nil {
			t.Fatalf("GenerateTOTPAt error: %v", err)
		}
		if code != tc.expected {
			t.Errorf("time %d: expected %s, got %s", tc.unix, tc.expected, code)
		}
	}
}

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

func TestTitoStruct_TOTPAndHOTP(t *testing.T) {
	opts := Options{Digits: 6, Period: 30, Algorithm: HashSHA1}
	tt := New(opts)

	// Use deterministic secret for test
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("01234567890123456789"))

	// TOTP: struct method
	now := time.Unix(1234567890, 0).UTC()
	code1, err := tt.GenerateTOTPAt(secret, now)
	if err != nil {
		t.Fatalf("GenerateTOTPAt error: %v", err)
	}
	code2, err := tt.GenerateTOTPAt(secret, now)
	if err != nil {
		t.Fatalf("Tito.GenerateTOTPAt error: %v", err)
	}
	if code1 != code2 {
		t.Fatalf("codes differ: %s vs %s", code1, code2)
	}

	// Validate via struct returns OK
	// Use a fixed clock matching 'now' so validation aligns
	tt.WithClock(fixedClock{t: now})
	res, err := tt.ValidateTOTP(secret, code2, 1)
	if err != nil {
		t.Fatalf("ValidateTOTP error: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected validation OK, got %+v", res)
	}

	// HOTP: struct vs function should match
	hotp1, err := GenerateHOTP(secret, 1, opts.Digits)
	if err != nil {
		t.Fatalf("GenerateHOTP error: %v", err)
	}
	hotp2, err := tt.GenerateHOTP(secret, 1)
	if err != nil {
		t.Fatalf("Tito.GenerateHOTP error: %v", err)
	}
	if hotp1 != hotp2 {
		t.Fatalf("HOTP codes differ: %s vs %s", hotp1, hotp2)
	}
}

func TestTitoStruct_URIAndQR(t *testing.T) {
	opts := Options{Digits: 6, Period: 30, Algorithm: HashSHA1}
	tt := New(opts)
	secret := tt.GenerateSecretFromSeed("seed")

	uri1, err := tt.BuildTOTPURI("Alice", "Acme", secret)
	if err != nil {
		t.Fatalf("Tito.BuildTOTPURI error: %v", err)
	}
	// Build again to ensure deterministic
	uri2, err := tt.BuildTOTPURI("Alice", "Acme", secret)
	if err != nil {
		t.Fatalf("Tito.BuildTOTPURI error: %v", err)
	}
	if uri1 != uri2 {
		t.Fatalf("URIs differ:\n%s\n%s", uri1, uri2)
	}

	// QR generation should produce non-empty PNG
	png, err := tt.QRPNGFor("Alice", "Acme", secret, 128)
	if err != nil {
		t.Fatalf("QRPNGFor error: %v", err)
	}
	if len(png) == 0 {
		t.Fatal("expected non-empty PNG bytes")
	}
	// very basic PNG header check
	if fmt.Sprintf("%x", png[:8]) != "89504e470d0a1a0a" {
		t.Fatalf("expected PNG header, got %x", png[:8])
	}
}

// RFC 6238 vectors for SHA256 and SHA512
func TestGenerateTOTP_RFC6238Vectors_SHA256(t *testing.T) {
	// 32-byte ASCII secret for SHA256
	secretASCII := "12345678901234567890123456789012"
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secretB32 := enc.EncodeToString([]byte(secretASCII))

	tests := []struct {
		unix     int64
		expected string
	}{
		{59, "46119246"},
		{1111111109, "68084774"},
		{1111111111, "67062674"},
		{1234567890, "91819424"},
		{2000000000, "90698825"},
		{20000000000, "77737706"},
	}

	tt := New(Options{Digits: 8, Period: 30, Algorithm: HashSHA256})
	for _, tc := range tests {
		code, err := tt.GenerateTOTPAt(secretB32, time.Unix(tc.unix, 0).UTC())
		if err != nil {
			t.Fatalf("GenerateTOTPAt error: %v", err)
		}
		if code != tc.expected {
			t.Errorf("time %d: expected %s, got %s", tc.unix, tc.expected, code)
		}
	}
}

func TestGenerateTOTP_RFC6238Vectors_SHA512(t *testing.T) {
	// 64-byte ASCII secret for SHA512
	secretASCII := "1234567890123456789012345678901234567890123456789012345678901234"
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secretB32 := enc.EncodeToString([]byte(secretASCII))

	tests := []struct {
		unix     int64
		expected string
	}{
		{59, "90693936"},
		{1111111109, "25091201"},
		{1111111111, "99943326"},
		{1234567890, "93441116"},
		{2000000000, "38618901"},
		{20000000000, "47863826"},
	}

	tt := New(Options{Digits: 8, Period: 30, Algorithm: HashSHA512})
	for _, tc := range tests {
		code, err := tt.GenerateTOTPAt(secretB32, time.Unix(tc.unix, 0).UTC())
		if err != nil {
			t.Fatalf("GenerateTOTPAt error: %v", err)
		}
		if code != tc.expected {
			t.Errorf("time %d: expected %s, got %s", tc.unix, tc.expected, code)
		}
	}
}

func TestGenerateTOTP_DigitsValidation(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret := enc.EncodeToString([]byte("01234567890123456789"))
	// digits < 6 should error
	ttBadLow := New(Options{Digits: 5, Period: 30})
	if _, err := ttBadLow.GenerateTOTPAt(secret, time.Unix(0, 0)); err == nil {
		t.Errorf("expected error for digits < 6")
	}
	// digits > 8 should error
	ttBadHigh := New(Options{Digits: 9, Period: 30})
	if _, err := ttBadHigh.GenerateTOTPAt(secret, time.Unix(0, 0)); err == nil {
		t.Errorf("expected error for digits > 8")
	}
}

func TestValidateTOTP_TimeWindow(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret := enc.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRST"))
	baseTime := time.Now().UTC().Truncate(30 * time.Second)

	tt := New(Options{Digits: 6, Period: 30})
	code, err := tt.GenerateTOTPAt(secret, baseTime)
	if err != nil {
		t.Fatalf("GenerateTOTPAt failed: %v", err)
	}

	if !ValidateTOTP(secret, code, baseTime, 6, 0) {
		t.Errorf("expected code to validate at base time with window 0")
	}
	if !ValidateTOTP(secret, code, baseTime.Add(30*time.Second), 6, 1) {
		t.Errorf("expected code to validate at +30s with window 1")
	}
	if ValidateTOTP(secret, code, baseTime.Add(60*time.Second), 6, 1) {
		t.Errorf("did not expect code to validate at +60s with window 1")
	}
	if ValidateTOTP(secret, code, baseTime, 6, -1) {
		t.Errorf("did not expect validation to pass with negative window")
	}
}

func TestGenerateSecretFromSeed_Format(t *testing.T) {
	tt := New(Options{})
	secret := tt.GenerateSecretFromSeed("seed value")
	if len(secret) != 32 {
		t.Fatalf("expected 32 chars, got %d", len(secret))
	}
	if strings.Contains(secret, "=") {
		t.Errorf("expected no '=' padding in secret: %s", secret)
	}
	// Should decode with no padding
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		t.Errorf("secret should be decodable: %v", err)
	}
}

func TestGenerateRandomSecret(t *testing.T) {
	s1, err := GenerateRandomSecret(20)
	if err != nil {
		t.Fatalf("GenerateRandomSecret error: %v", err)
	}
	if len(s1) == 0 {
		t.Fatal("expected non-empty secret")
	}
	if strings.Contains(s1, "=") {
		t.Errorf("expected no '=' padding: %s", s1)
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s1); err != nil {
		t.Errorf("secret should decode: %v", err)
	}

	s2, err := GenerateRandomSecret(20)
	if err != nil {
		t.Fatalf("GenerateRandomSecret error: %v", err)
	}
	if s1 == s2 {
		t.Errorf("expected different secrets across invocations")
	}
}

func TestSecretNormalization_AcceptsLowercaseAndSpaces(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret := enc.EncodeToString([]byte("01234567890123456789"))
	// Insert spaces and make lowercase and add '=' padding
	noisy := strings.ToLower(secret[:8]+" "+secret[8:16]+" "+secret[16:]) + "==="

	tt := New(Options{Digits: 6, Period: 30})
	refTime := time.Unix(1234567890, 0).UTC()
	want, err := tt.GenerateTOTPAt(secret, refTime)
	if err != nil {
		t.Fatalf("GenerateTOTP ref failed: %v", err)
	}
	got, err := tt.GenerateTOTPAt(noisy, refTime)
	if err != nil {
		t.Fatalf("GenerateTOTP noisy failed: %v", err)
	}
	if want != got {
		t.Errorf("expected normalized secret to match: want %s got %s", want, got)
	}
}
