package tito

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// HashAlgorithm selects the underlying HMAC hash for TOTP per RFC 6238.
type HashAlgorithm int

const (
	HashSHA1 HashAlgorithm = iota
	HashSHA256
	HashSHA512
)

// generateTOTPWithHash generates a TOTP using the selected hash algorithm.
func generateTOTPWithHash(secret string, timestamp time.Time, digits int, algo HashAlgorithm) (string, error) {
	// Validate digits
	if digits < 6 || digits > 8 {
		return "", fmt.Errorf("invalid digits: %d (must be between 6 and 8)", digits)
	}

	// Normalize and decode the base32 secret (no padding)
	normalized := normalizeBase32Secret(secret)
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := decoder.DecodeString(normalized)
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

	// Select HMAC hash implementation
	var mac func() hash.Hash
	switch algo {
	case HashSHA1:
		mac = sha1.New
	case HashSHA256:
		mac = sha256.New
	case HashSHA512:
		mac = sha512.New
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %d", algo)
	}

	h := hmac.New(mac, key)
	h.Write(counterBytes)
	fullHash := h.Sum(nil)

	// Truncate the hash to get the OTP
	offset := fullHash[len(fullHash)-1] & 0xf
	binary := ((int(fullHash[offset]) & 0x7f) << 24) |
		((int(fullHash[offset+1]) & 0xff) << 16) |
		((int(fullHash[offset+2]) & 0xff) << 8) |
		(int(fullHash[offset+3]) & 0xff)

	// Generate the OTP code with the specified number of digits
	otp := binary % int(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, otp), nil
}

// Deprecated: use (*Tito).GenerateTOTPAt or (*Tito).GenerateTOTP instead.
// func GenerateTOTP(secret string, timestamp time.Time, digits int) (string, error) {
// 	return generateTOTPWithHash(secret, timestamp, digits, HashSHA1)
// }

func ValidateTOTP(secret, userCode string, timestamp time.Time, digits int, timeWindow int) bool {
	return validateTOTPWithHash(secret, userCode, timestamp, digits, timeWindow, HashSHA1)
}

// validateTOTPWithHash validates the provided code across a time window using the selected hash algorithm.
func validateTOTPWithHash(secret, userCode string, timestamp time.Time, digits int, timeWindow int, algo HashAlgorithm) bool {
	timeStep := int64(30) // 30 seconds is the default time step

	if timeWindow < 0 {
		return false
	}

	// Check the OTP for the current, previous, and next time steps
	for i := -timeWindow; i <= timeWindow; i++ {
		// Calculate the time for the current step
		stepTime := timestamp.Add(time.Duration(i) * time.Second * time.Duration(timeStep))

		// Generate the TOTP code for the current step
		code, err := generateTOTPWithHash(secret, stepTime, digits, algo)
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

// trimPadding removes padding characters ('=') from the Base32 string.
func trimPadding(s string) string {
	return string(bytes.TrimRight([]byte(s), "="))
}

// normalizeBase32Secret uppercases, removes spaces, dashes, and padding to support no-padding decoding.
func normalizeBase32Secret(s string) string {
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "=", "")
	return s
}

// GenerateRandomSecret returns a Base32 (no padding) encoded random secret with nBytes entropy.
func GenerateRandomSecret(nBytes int) (string, error) {
	if nBytes <= 0 {
		return "", fmt.Errorf("nBytes must be > 0")
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %v", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(buf), nil
}

// Options controls TOTP/HOTP generation and validation parameters.
type Options struct {
	Digits    int
	Period    int           // seconds, default 30
	T0        int64         // Unix epoch for counter start, default 0
	Algorithm HashAlgorithm // default SHA1
}

func (o *Options) setDefaultsIfZero() {
	if o.Digits == 0 {
		o.Digits = 6
	}
	if o.Period == 0 {
		o.Period = 30
	}
}

// ValidateResult contains detailed validation outcome.
type ValidateResult struct {
	OK   bool
	Skew int // steps offset from provided timestamp (0 means exact step)
}

// ValidateTOTPWithOpts validates TOTP across a window using options and returns details.
func ValidateTOTPWithOpts(secret, userCode string, t time.Time, window int, opts Options) (ValidateResult, error) {
	opts.setDefaultsIfZero()
	if window < 0 {
		return ValidateResult{OK: false}, nil
	}
	period := int64(opts.Period)
	if period <= 0 {
		return ValidateResult{}, fmt.Errorf("invalid period: %d", opts.Period)
	}

	for i := -window; i <= window; i++ {
		stepTime := time.Unix(t.Unix()+int64(i)*period, 0).UTC()
		// inline former GenerateTOTPWithOpts
		counter := uint64((stepTime.Unix() - opts.T0) / period)
		code, err := GenerateHOTPWithHash(secret, counter, opts.Digits, opts.Algorithm)
		if err != nil {
			continue
		}
		if ConstantTimeEqual(code, userCode) {
			return ValidateResult{OK: true, Skew: i}, nil
		}
	}
	return ValidateResult{OK: false, Skew: 0}, nil
}

// ConstantTimeEqual compares codes in constant time.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Clock interface to allow custom time sources for testing/drift control.
type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// InMemoryReuseProtector prevents code reuse within a step by tracking seen counters per key.
type InMemoryReuseProtector struct{ seen map[string]uint64 }

func NewInMemoryReuseProtector() *InMemoryReuseProtector {
	return &InMemoryReuseProtector{seen: map[string]uint64{}}
}

// MarkAndCheck returns false if provided counter is less than or equal to last seen for key.
func (p *InMemoryReuseProtector) MarkAndCheck(key string, counter uint64) bool {
	last, ok := p.seen[key]
	if ok && counter <= last {
		return false
	}
	p.seen[key] = counter
	return true
}

// Recovery code helpers
func GenerateRecoveryCodes(n int, length int) ([]string, error) {
	if n <= 0 || length < 6 {
		return nil, fmt.Errorf("invalid args")
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codes := make([]string, n)
	buf := make([]byte, length)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		for j := 0; j < length; j++ {
			buf[j] = alphabet[int(buf[j])%len(alphabet)]
		}
		codes[i] = string(buf)
	}
	return codes, nil
}

// Simple in-memory rate limiter (token-per-interval)
type SimpleRateLimiter struct {
	last     time.Time
	interval time.Duration
}

func NewSimpleRateLimiter(interval time.Duration) *SimpleRateLimiter {
	return &SimpleRateLimiter{interval: interval}
}
func (r *SimpleRateLimiter) Allow(now time.Time) bool {
	if r.last.IsZero() || now.Sub(r.last) >= r.interval {
		r.last = now
		return true
	}
	return false
}

// Flexible secret decoding: tries Base32 (no padding), Hex, Base64 Std/URL.
func DecodeFlexibleSecret(s string) ([]byte, error) {
	// Try Base32 (normalize, no padding)
	if s != "" {
		if key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalizeBase32Secret(s)); err == nil {
			return key, nil
		}
	}
	// Try hex
	if b, err := hex.DecodeString(strings.TrimSpace(s)); err == nil {
		return b, nil
	}
	// Try Base64 Std
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s)); err == nil {
		return b, nil
	}
	// Try Base64 URL
	if b, err := base64.URLEncoding.DecodeString(strings.TrimSpace(s)); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("failed to decode secret with supported encodings")
}

// HOTP (RFC 4226)
func GenerateHOTP(secret string, counter uint64, digits int) (string, error) {
	return GenerateHOTPWithHash(secret, counter, digits, HashSHA1)
}

func GenerateHOTPWithHash(secret string, counter uint64, digits int, algo HashAlgorithm) (string, error) {
	if digits < 6 || digits > 8 {
		return "", fmt.Errorf("invalid digits: %d (must be between 6 and 8)", digits)
	}
	// decode secret flexibly
	key, err := DecodeFlexibleSecret(secret)
	if err != nil {
		return "", err
	}
	// counter bytes
	counterBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter >>= 8
	}
	var mac func() hash.Hash
	switch algo {
	case HashSHA1:
		mac = sha1.New
	case HashSHA256:
		mac = sha256.New
	case HashSHA512:
		mac = sha512.New
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %d", algo)
	}
	h := hmac.New(mac, key)
	h.Write(counterBytes)
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binary := ((int(sum[offset]) & 0x7f) << 24) | ((int(sum[offset+1]) & 0xff) << 16) | ((int(sum[offset+2]) & 0xff) << 8) | (int(sum[offset+3]) & 0xff)
	otp := binary % int(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, otp), nil
}

func ValidateHOTP(secret string, counter uint64, userCode string, digits int, lookAhead uint64) (bool, uint64) {
	// Check current and next lookAhead counters; return matched counter if found
	for i := uint64(0); i <= lookAhead; i++ {
		code, err := GenerateHOTP(secret, counter+i, digits)
		if err != nil {
			continue
		}
		if ConstantTimeEqual(code, userCode) {
			return true, counter + i
		}
	}
	return false, counter
}

// otpauth URI helpers (TOTP and HOTP)

type OTPAuth struct {
	Type      string // totp or hotp
	Label     string
	Issuer    string
	Secret    string
	Digits    int
	Period    int
	Algorithm HashAlgorithm
	Counter   uint64 // for HOTP
}

func ParseOTPAuthURI(uri string) (OTPAuth, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return OTPAuth{}, err
	}
	if u.Scheme != "otpauth" {
		return OTPAuth{}, fmt.Errorf("invalid scheme: %s", u.Scheme)
	}
	typ := u.Host
	label := strings.TrimPrefix(u.EscapedPath(), "/")
	label, _ = url.PathUnescape(label)
	q := u.Query()
	issuer := q.Get("issuer")
	secret := q.Get("secret")
	digits, _ := strconv.Atoi(q.Get("digits"))
	if digits == 0 {
		digits = 6
	}
	period, _ := strconv.Atoi(q.Get("period"))
	if period == 0 {
		period = 30
	}
	var algo HashAlgorithm = HashSHA1
	switch strings.ToUpper(q.Get("algorithm")) {
	case "SHA256":
		algo = HashSHA256
	case "SHA512":
		algo = HashSHA512
	}
	var counter uint64
	if c := q.Get("counter"); c != "" {
		if v, err := strconv.ParseUint(c, 10, 64); err == nil {
			counter = v
		}
	}
	return OTPAuth{Type: typ, Label: label, Issuer: issuer, Secret: secret, Digits: digits, Period: period, Algorithm: algo, Counter: counter}, nil
}

// QR code generation for provisioning (PNG bytes)
// Uses github.com/skip2/go-qrcode
func QRPNGFromURI(uri string, size int) ([]byte, error) {
	if size <= 0 {
		size = 256
	}
	// lazy import at top-level; implementation here calls package
	png, err := qrcode.Encode(uri, qrcode.Medium, size)
	if err != nil {
		return nil, err
	}
	return png, nil
}

// Tito provides a struct-based API for TOTP/HOTP operations with configuration and helpers.
type Tito struct {
	Options     Options
	Clock       Clock
	ReuseGuard  *InMemoryReuseProtector
	RateLimiter *SimpleRateLimiter
}

// New constructs a Tito instance with defaults applied.
func New(opts Options) *Tito {
	opts.setDefaultsIfZero()
	return &Tito{
		Options: opts,
		Clock:   systemClock{},
	}
}

// WithClock sets a custom clock and returns the same instance for chaining.
func (t *Tito) WithClock(c Clock) *Tito { t.Clock = c; return t }

// WithReuseGuard sets a reuse protector and returns the same instance.
func (t *Tito) WithReuseGuard(g *InMemoryReuseProtector) *Tito { t.ReuseGuard = g; return t }

// WithRateLimiter sets a rate limiter and returns the same instance.
func (t *Tito) WithRateLimiter(r *SimpleRateLimiter) *Tito { t.RateLimiter = r; return t }

// GenerateSecretFromSeed generates a Base32-encoded secret from a seed string (method form).
func (t *Tito) GenerateSecretFromSeed(seed string) string {
	hash := sha256.Sum256([]byte(seed))
	raw := hash[:20]
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(raw)
}

// GenerateTOTP generates a TOTP for the current time using the instance options.
func (t *Tito) GenerateTOTP(secret string) (string, error) {
	now := t.now()
	return t.GenerateTOTPAt(secret, now)
}

// GenerateTOTPAt generates a TOTP for a provided time.
func (t *Tito) GenerateTOTPAt(secret string, at time.Time) (string, error) {
	// compute counter using Period and T0 via options
	t.Options.setDefaultsIfZero()
	period := int64(t.Options.Period)
	if period <= 0 {
		return "", fmt.Errorf("invalid period: %d", t.Options.Period)
	}
	counter := uint64((at.Unix() - t.Options.T0) / period)
	return GenerateHOTPWithHash(secret, counter, t.Options.Digits, t.Options.Algorithm)
}

// ValidateTOTP validates a code at the current time with the provided window (in steps).
func (t *Tito) ValidateTOTP(secret, code string, window int) (ValidateResult, error) {
	if t.RateLimiter != nil && !t.RateLimiter.Allow(t.now()) {
		return ValidateResult{OK: false}, nil
	}
	return ValidateTOTPWithOpts(secret, code, t.now(), window, t.Options)
}

// GenerateHOTP generates an HOTP using the instance digits and algorithm.
func (t *Tito) GenerateHOTP(secret string, counter uint64) (string, error) {
	return GenerateHOTPWithHash(secret, counter, t.Options.Digits, t.Options.Algorithm)
}

// ValidateHOTP validates an HOTP code allowing a look-ahead window.
func (t *Tito) ValidateHOTP(secret, code string, counter uint64, lookAhead uint64) (bool, uint64) {
	if t.RateLimiter != nil && !t.RateLimiter.Allow(t.now()) {
		return false, counter
	}
	ok, matched := ValidateHOTP(secret, counter, code, t.Options.Digits, lookAhead)
	if ok && t.ReuseGuard != nil {
		if !t.ReuseGuard.MarkAndCheck(secret, matched) {
			return false, counter
		}
	}
	return ok, matched
}

// BuildTOTPURI builds an otpauth URI using instance options.
func (t *Tito) BuildTOTPURI(label, issuer, secret string) (string, error) {
	t.Options.setDefaultsIfZero()
	v := url.Values{}
	v.Set("secret", normalizeBase32Secret(secret))
	v.Set("issuer", issuer)
	v.Set("digits", strconv.Itoa(t.Options.Digits))
	v.Set("period", strconv.Itoa(t.Options.Period))
	switch t.Options.Algorithm {
	case HashSHA1:
		v.Set("algorithm", "SHA1")
	case HashSHA256:
		v.Set("algorithm", "SHA256")
	case HashSHA512:
		v.Set("algorithm", "SHA512")
	}
	return (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + url.PathEscape(label), RawQuery: v.Encode()}).String(), nil
}

// BuildHOTPURI builds an otpauth HOTP URI using instance options.
func (t *Tito) BuildHOTPURI(label, issuer, secret string, counter uint64) (string, error) {
	v := url.Values{}
	v.Set("secret", normalizeBase32Secret(secret))
	v.Set("issuer", issuer)
	v.Set("digits", strconv.Itoa(t.Options.Digits))
	v.Set("counter", strconv.FormatUint(counter, 10))
	switch t.Options.Algorithm {
	case HashSHA1:
		v.Set("algorithm", "SHA1")
	case HashSHA256:
		v.Set("algorithm", "SHA256")
	case HashSHA512:
		v.Set("algorithm", "SHA512")
	}
	return (&url.URL{Scheme: "otpauth", Host: "hotp", Path: "/" + url.PathEscape(label), RawQuery: v.Encode()}).String(), nil
}

// QRPNGFor generates a QR PNG for the given otpauth TOTP parameters.
func (t *Tito) QRPNGFor(label, issuer, secret string, size int) ([]byte, error) {
	uri, err := t.BuildTOTPURI(label, issuer, secret)
	if err != nil {
		return nil, err
	}
	return QRPNGFromURI(uri, size)
}

func (t *Tito) now() time.Time {
	if t.Clock == nil {
		return time.Now().UTC()
	}
	return t.Clock.Now()
}
