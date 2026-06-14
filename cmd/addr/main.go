package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ripemd160"
)

func mainWithErr() error {
	mnemonic := "beach snow mirror home noble come onion toward ice vague faculty fence"
	passphrase := ""
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return errors.Wrap(err, "")
	}

	// descriptor id
	privKeyAt0, err := deriveKeyAtPath(masterKey, "m/84'/1'/0'/0/0")
	if err != nil {
		return errors.Wrap(err, "")
	}
	pubKeyAt0 := privKeyAt0.PublicKey()
	wp := WitnessProgram{Version: OP_0, Program: hash160(pubKeyAt0.Key)}
	spk := wp.ScriptPubKey()
	did := sha256Str(spk)
	log.Printf("did %s", did)
	log.Printf("!!! %v", "d0e866b4327ed13e69ff0764e67e5ae98ad209375772470de4a604709e3eaf5e" == did)

	return nil
}

var (
	OP_0 byte = 0x00
)

type WitnessProgram struct {
	Version byte
	Program []byte
}

func (wp WitnessProgram) ScriptPubKey() []byte {
	b := bytes.NewBuffer(nil)
	b.WriteByte(wp.Version)

	plen := len(wp.Program)
	switch {
	case plen < 0x4c:
		b.WriteByte(byte(plen))
	case plen < 0xff:
		b.Write([]byte{0x4c, byte(plen)})
	case plen < 0xffff:
		b.Write([]byte{0x4d, byte(plen), byte(plen >> 8)})
	case plen < 0xffffffff:
		b.Write([]byte{0x4e, byte(plen), byte(plen >> 8), byte(plen >> 16)})
	default:
		panic("data too large")
	}
	b.Write(wp.Program)

	return b.Bytes()
}

func hash160(b []byte) []byte {
	s256 := sha256.New()
	s256.Write(b)
	b = s256.Sum(nil)

	r160 := ripemd160.New()
	r160.Write(b)
	b = r160.Sum(nil)

	return b
}

func sha256Str(b []byte) string {
	b256 := sha256.Sum256(b)
	return hex.EncodeToString(b256[:])
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

func main() {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds | log.Llongfile | log.LstdFlags)

	if err := mainWithErr(); err != nil {
		log.Fatalf("%+v", err)
	}
}
