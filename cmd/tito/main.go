package main

import (
	"flag"
	"fmt"
	"os"

	"tito"
)

func main() {
	mode := flag.String("mode", "totp", "totp|hotp|uri|qr")
	secret := flag.String("secret", "", "secret in Base32/hex/base64")
	digits := flag.Int("digits", 6, "digits (6-8)")
	period := flag.Int("period", 30, "period seconds (TOTP)")
	counter := flag.Uint64("counter", 0, "counter (HOTP)")
	label := flag.String("label", "Account", "label for URI")
	issuer := flag.String("issuer", "Example", "issuer for URI")
	flag.Parse()

	t := tito.New(tito.Options{Digits: *digits, Period: *period})

	if *mode == "totp" {
		code, err := t.GenerateTOTP(*secret)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(code)
		return
	}
	if *mode == "hotp" {
		code, err := tito.GenerateHOTP(*secret, *counter, *digits)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(code)
		return
	}
	if *mode == "uri" {
		uri, err := t.BuildTOTPURI(*label, *issuer, *secret)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(uri)
		return
	}
	if *mode == "qr" {
		uri, err := t.BuildTOTPURI(*label, *issuer, *secret)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		png, err := tito.QRPNGFromURI(uri, 256)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(png); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "unknown mode")
	os.Exit(1)
}
