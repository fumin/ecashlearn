package bip380

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/fumin/ecashlearn/bech32"
	"github.com/fumin/ecashlearn/crypto"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var (
	OP_0 byte = 0

	BIP32VersionMainnetPublic, _  = hex.DecodeString("0488B21E")
	BIP32VersionMainnetPrivate, _ = hex.DecodeString("0488ADE4")
	BIP32VersionTestnetPublic, _  = hex.DecodeString("043587CF")
	BIP32VersionTestnetPrivate, _ = hex.DecodeString("04358394")
)

func wpkhAddress(mnemonic, passphrase, derivationPath, humanReadablePart string) (string, error) {
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return "", errors.Wrap(err, "")
	}
	privKey, err := deriveKeyAtPath(masterKey, derivationPath)
	if err != nil {
		return "", errors.Wrap(err, "")
	}
	pubKey := privKey.PublicKey()
	witnessVersion := int(OP_0)
	witnessProgram := crypto.Hash160(pubKey.Key)
	address, err := bech32.SegwitAddrEncode(humanReadablePart, witnessVersion, witnessProgram)
	if err != nil {
		return "", errors.Wrap(err, "")
	}
	return address, nil
}

func getXpub(mnemonic, passphrase, derivationPath string, version []byte) string {
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return ""
	}
	privKey, err := deriveKeyAtPath(masterKey, derivationPath)
	if err != nil {
		return ""
	}
	pubKey := privKey.PublicKey()
	pubKey.Version = version
	return pubKey.B58Serialize()
}

func getFingerprint(mnemonic, passphrase string) string {
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return ""
	}
	pubKey := masterKey.PublicKey()
	keyIdentifier := crypto.Hash160(pubKey.Key)
	fingerprint := hex.EncodeToString(keyIdentifier)
	return fingerprint[:8]
}

func descriptorChecksum(span string) string {
	const (
		inputCharset = "0123456789()[],'/*abcdefgh@:$%{}" +
			"IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
			"ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
		checksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	)

	var c uint64 = 1
	var cls, clscount int
	for _, ch := range span {
		pos := strings.IndexRune(inputCharset, ch)
		if pos == -1 {
			return ""
		}
		c = polyMod(c, pos&31)
		cls = cls*3 + (pos >> 5)
		clscount++
		if clscount == 3 {
			c = polyMod(c, cls)
			cls = 0
			clscount = 0
		}
	}
	if clscount > 0 {
		c = polyMod(c, cls)
	}
	for range 8 {
		c = polyMod(c, 0)
	}
	c ^= 1

	ret := make([]byte, 8)
	for j := range 8 {
		ret[j] = checksumCharset[(c>>(5*(7-j)))&31]
	}
	return string(ret)
}

func polyMod(c uint64, val int) uint64 {
	var c0 uint64 = (c >> 35)
	c = ((c & 0x7ffffffff) << 5) ^ uint64(val)
	if (c0 & 1) != 0 {
		c ^= 0xf5dee51989
	}
	if (c0 & 2) != 0 {
		c ^= 0xa9fdca3312
	}
	if (c0 & 4) != 0 {
		c ^= 0x1bab10e32d
	}
	if (c0 & 8) != 0 {
		c ^= 0x3706b1677a
	}
	if (c0 & 16) != 0 {
		c ^= 0x644d626ffd
	}
	return c
}

func deriveKeyAtPath(masterKey *bip32.Key, path string) (*bip32.Key, error) {
	// Remove "m/" prefix
	path = strings.TrimPrefix(path, "m/")
	if path == "" || path == "m" {
		return masterKey, nil
	}

	components := strings.Split(path, "/")
	key := masterKey

	for _, component := range components {
		hardened := strings.HasSuffix(component, "'")
		component = strings.TrimSuffix(component, "'")

		var index uint32
		_, err := fmt.Sscanf(component, "%d", &index)
		if err != nil {
			return nil, fmt.Errorf("parse path component %q: %w", component, err)
		}

		if hardened {
			index += bip32.FirstHardenedChild
		}

		key, err = key.NewChildKey(index)
		if err != nil {
			return nil, fmt.Errorf("derive child %d: %w", index, err)
		}
	}

	return key, nil
}
