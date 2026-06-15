package bip380

import (
	"flag"
	"fmt"
	"log"
	"testing"

	"github.com/fumin/ecashlearn/bech32"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func TestWpkhAddress(t *testing.T) {
	tests := []struct {
		mnemonic          string
		passphrase        string
		derivationPath    string
		humanReadablePart string
		address           string
	}{
		{
			mnemonic:          "beach snow mirror home noble come onion toward ice vague faculty fence",
			passphrase:        "",
			derivationPath:    "m/84'/1'/0'/0/0",
			humanReadablePart: bech32.HumanReadablePartTestnet,
			address:           "tb1qxca2qjjem35a9jlyheemnvwgp6y3n4e59z7epl",
		},
		{
			mnemonic:          "beach snow mirror home noble come onion toward ice vague faculty fence",
			passphrase:        "",
			derivationPath:    "m/84'/1'/0'/1/0",
			humanReadablePart: bech32.HumanReadablePartTestnet,
			address:           "tb1qugycxzgw82z4q5trjn2a3pf354q7d8tqejtzg0",
		},
		{
			mnemonic:          "beach snow mirror home noble come onion toward ice vague faculty fence",
			passphrase:        "",
			derivationPath:    "m/84'/1'/0'/1/1",
			humanReadablePart: bech32.HumanReadablePartTestnet,
			address:           "tb1q684a8d3ydk2j9hyxdpyl2j5zy4788a2yv3wnsl",
		},
		{
			mnemonic:          "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
			passphrase:        "",
			derivationPath:    "m/84'/1'/0'/0/0",
			humanReadablePart: bech32.HumanReadablePartTestnet,
			address:           "tb1qu7ezehw6ryu5x45cszn47alyhpm0f0z9e8eeaf",
		},
		{
			mnemonic:          "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
			passphrase:        "",
			derivationPath:    "m/84'/1'/0'/1/0",
			humanReadablePart: bech32.HumanReadablePartTestnet,
			address:           "tb1qffa2erlg76h4vj7tf4jycx625wwzn0lta0p67z",
		},
		{
			mnemonic:          "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
			passphrase:        "",
			derivationPath:    "m/84'/1'/0'/1/1",
			humanReadablePart: bech32.HumanReadablePartTestnet,
			address:           "tb1qrfe35dakhev25mvqjyxajj2v8yq2ldfyxkejcp",
		},
		{
			mnemonic:          "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
			passphrase:        "",
			derivationPath:    "m/84'/1'/0'/1/2",
			humanReadablePart: bech32.HumanReadablePartTestnet,
			address:           "tb1qcjvzx05mhehg7nk0q8sevxmh747ez9thzn42vy",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			_, address, err := WpkhAddress(test.mnemonic, test.passphrase, test.derivationPath, test.humanReadablePart)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if address != test.address {
				t.Errorf("WpkhAddress(%s, %s, %s, %s) = %s want %s", test.mnemonic, test.passphrase, test.derivationPath, test.humanReadablePart, address, test.address)
			}
		})
	}
}

func TestDeriveKeyAtPath(t *testing.T) {
	tests := []struct {
		mnemonic   string
		passphrase string
		paths0     []string
		paths1     []string
	}{
		{
			mnemonic:   "beach snow mirror home noble come onion toward ice vague faculty fence",
			passphrase: "",
			paths0:     []string{"m/84'/1'/0'", "m/0/0"},
			paths1:     []string{"m/84'/1'/0'/0/0"},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			k0, err := deriveKey(test.mnemonic, test.passphrase, test.paths0)
			if err != nil {
				t.Errorf("%+v", err)
			}
			k1, err := deriveKey(test.mnemonic, test.passphrase, test.paths1)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if k0 != k1 {
				t.Errorf("%s != %s", k0, k1)
			}
		})
	}
}

func deriveKey(mnemonic, passphrase string, derivationPaths []string) (string, error) {
	seed := bip39.NewSeed(mnemonic, passphrase)
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return "", errors.Wrap(err, "")
	}
	for i, path := range derivationPaths {
		key, err = deriveKeyAtPath(key, path)
		if err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("%d %s", i, path))
		}
	}
	return key.String(), nil
}

func TestGetXpub(t *testing.T) {
	tests := []struct {
		mnemonic       string
		passphrase     string
		derivationPath string
		version        []byte
		xpub           string
	}{
		{
			mnemonic:       "beach snow mirror home noble come onion toward ice vague faculty fence",
			passphrase:     "",
			derivationPath: "m/84'/1'/0'",
			version:        BIP32VersionTestnetPublic,
			xpub:           "tpubDCio35v4j25tXrXqQjFHkPjsx1G2tn1hPpVkJN1VW1qtN3rjeBCkH7pYsDXrgPE1JWiJ1b51TjQu4nhNLHA9ktQZbUFyjej5N4xKNx2kGNK",
		},
		{
			mnemonic:       "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
			passphrase:     "",
			derivationPath: "m/84'/1'/0'",
			version:        BIP32VersionTestnetPublic,
			xpub:           "tpubDCK4H6N5UxZGqYJRhW7qkxhtZxnFpZfyocpTLx98g3qDV5FCMUN7vRH5KopkaGDJ3q4bnMbViffZRhdFvQD9aGgQQZwcJ5dRxnGJNrkq1fe",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			xpub := getXpub(test.mnemonic, test.passphrase, test.derivationPath, test.version)
			if xpub != test.xpub {
				t.Errorf("getXpub(%s, %s, %s, %v) = %s want %s", test.mnemonic, test.passphrase, test.derivationPath, test.version, xpub, test.xpub)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	tests := []struct {
		mnemonic    string
		passphrase  string
		fingerprint string
	}{
		{
			mnemonic:    "beach snow mirror home noble come onion toward ice vague faculty fence",
			passphrase:  "",
			fingerprint: "143593ae",
		},
		{
			mnemonic:    "leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor",
			passphrase:  "",
			fingerprint: "81e113be",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			fingerprint := getFingerprint(test.mnemonic, test.passphrase)
			if fingerprint != test.fingerprint {
				t.Errorf("getFingerprint(%s, %s) = %s want %s", test.mnemonic, test.passphrase, fingerprint, test.fingerprint)
			}
		})
	}
}

func TestDescriptorChecksum(t *testing.T) {
	tests := []struct {
		descriptor string
		checksum   string
	}{
		{
			descriptor: "raw(deadbeef)",
			checksum:   "89f8spxm",
		},
		{

			descriptor: "wpkh([143593ae/84'/1'/0']tpubDCio35v4j25tXrXqQjFHkPjsx1G2tn1hPpVkJN1VW1qtN3rjeBCkH7pYsDXrgPE1JWiJ1b51TjQu4nhNLHA9ktQZbUFyjej5N4xKNx2kGNK/0/*)",
			checksum:   "5lxgjflg",
		},
		{
			descriptor: "wpkh([143593ae/84'/1'/0']tpubDCio35v4j25tXrXqQjFHkPjsx1G2tn1hPpVkJN1VW1qtN3rjeBCkH7pYsDXrgPE1JWiJ1b51TjQu4nhNLHA9ktQZbUFyjej5N4xKNx2kGNK/1/*)",
			checksum:   "9trf0u0s",
		},
		{
			descriptor: "wpkh([81e113be/84'/1'/0']tpubDCK4H6N5UxZGqYJRhW7qkxhtZxnFpZfyocpTLx98g3qDV5FCMUN7vRH5KopkaGDJ3q4bnMbViffZRhdFvQD9aGgQQZwcJ5dRxnGJNrkq1fe/0/*)",
			checksum:   "y259pe3g",
		},
		{
			descriptor: "wpkh([81e113be/84'/1'/0']tpubDCK4H6N5UxZGqYJRhW7qkxhtZxnFpZfyocpTLx98g3qDV5FCMUN7vRH5KopkaGDJ3q4bnMbViffZRhdFvQD9aGgQQZwcJ5dRxnGJNrkq1fe/1/*)",
			checksum:   "473yuvps",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			checksum := descriptorChecksum(test.descriptor)

			if checksum != test.checksum {
				t.Errorf("DescriptorChecksum(%s) = %s want %s", test.descriptor, checksum, test.checksum)
			}
		})
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds | log.Llongfile | log.LstdFlags)

	m.Run()
}
