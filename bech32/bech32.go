package bech32

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/fumin/ecashlearn/script"
	"github.com/pkg/errors"
)

type Encoding byte

const (
	EncodingNone    Encoding = 0
	EncodingBech32  Encoding = 1
	EncodingBech32m Encoding = 2

	HumanReadablePartMainnet = "bc"
	HumanReadablePartTestnet = "tb"

	charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
)

var (
	generator = []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
)

func polymod(values []uint32) uint32 {
	var chk uint32 = 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

func hrpExpand(hrp string) []uint32 {
	ret := []uint32{}
	for _, c := range hrp {
		ret = append(ret, uint32(c)>>5)
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, uint32(c)&31)
	}
	return ret
}

func checksumEncoding(hrp string, data []byte) (uint32, Encoding) {
	values := hrpExpand(hrp)
	for _, c := range data {
		values = append(values, uint32(c))
	}
	chk := polymod(values)
	switch chk {
	case finalConstant(EncodingBech32):
		return chk, EncodingBech32
	case finalConstant(EncodingBech32m):
		return chk, EncodingBech32m
	default:
		return chk, EncodingNone
	}
}

func createChecksum(hrp string, data []byte, enc Encoding) []byte {
	values := hrpExpand(hrp)
	for _, c := range data {
		values = append(values, uint32(c))
	}
	values = append(values, []uint32{0, 0, 0, 0, 0, 0}...)
	mod := polymod(values) ^ finalConstant(enc)
	ret := make([]byte, 6)
	for p := range ret {
		ret[p] = byte((mod >> uint(5*(5-p))) & 31)
	}
	return ret
}

// Encode encodes hrp(human-readable part) and data(32bit data array), returns Bech32 / or error
func Encode(hrp string, data []byte, enc Encoding) (string, error) {
	if (len(hrp) + len(data) + 7) > 90 {
		return "", errors.Errorf("too long : hrp length=%d, data length=%d", len(hrp), len(data))
	}
	if len(hrp) < 1 {
		return "", errors.Errorf("invalid hrp : hrp=%v", hrp)
	}
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return "", errors.Errorf("invalid character human-readable part : hrp[%d]=%d", p, c)
		}
		if c >= 'A' && c <= 'Z' {
			return "", errors.Errorf("invalid character human-readable part : hrp[%d]=%d", p, c)
		}
	}
	if strings.ToUpper(hrp) != hrp && strings.ToLower(hrp) != hrp {
		return "", errors.Errorf("mix case : hrp=%v", hrp)
	}
	hrp = strings.ToLower(hrp)
	combined := append(data, createChecksum(hrp, data, enc)...)
	var ret bytes.Buffer
	ret.WriteString(hrp)
	ret.WriteString("1")
	for idx, p := range combined {
		if p < 0 || int(p) >= len(charset) {
			return "", errors.Errorf("invalid data : data[%d]=%d", idx, p)
		}
		ret.WriteByte(charset[p])
	}
	return ret.String(), nil
}

// Decode decodes bechString(Bech32) returns hrp(human-readable part) and data(32bit data array) / or error
func Decode(bechString string) (string, []byte, Encoding, error) {
	if len(bechString) > 90 {
		return "", nil, EncodingNone, errors.Errorf("too long : len=%d", len(bechString))
	}
	if strings.ToLower(bechString) != bechString && strings.ToUpper(bechString) != bechString {
		return "", nil, EncodingNone, errors.Errorf("mixed case")
	}
	bechString = strings.ToLower(bechString)
	pos := strings.LastIndex(bechString, "1")
	if pos < 1 || pos+7 > len(bechString) {
		return "", nil, EncodingNone, errors.Errorf("separator '1' at invalid position : pos=%d , len=%d", pos, len(bechString))
	}
	hrp := bechString[0:pos]
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, EncodingNone, errors.Errorf("invalid character human-readable part : bechString[%d]=%d", p, c)
		}
	}
	data := []byte{}
	for p := pos + 1; p < len(bechString); p++ {
		d := strings.Index(charset, fmt.Sprintf("%c", bechString[p]))
		if d == -1 {
			return "", nil, EncodingNone, errors.Errorf("invalid character data part : bechString[%d]=%d", p, bechString[p])
		}
		data = append(data, byte(d))
	}
	chk, enc := checksumEncoding(hrp, data)
	if enc == EncodingNone {
		return "", nil, EncodingNone, errors.Errorf("invalid checksum %d", chk)
	}
	return hrp, data[:len(data)-6], enc, nil
}

func convertbits(data []byte, frombits, tobits uint, pad bool) ([]byte, error) {
	var acc uint32
	bits := uint(0)
	ret := []byte{}
	var maxv uint32 = (1 << tobits) - 1
	for idx, value := range data {
		if value < 0 || (value>>frombits) != 0 {
			return nil, errors.Errorf("invalid data range : data[%d]=%d (frombits=%d)", idx, value, frombits)
		}
		acc = (acc << frombits) | uint32(value)
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(tobits-bits))&maxv))
		}
	} else if bits >= frombits {
		return nil, errors.Errorf("illegal zero padding")
	} else if ((acc << (tobits - bits)) & maxv) != 0 {
		return nil, errors.Errorf("non-zero padding")
	}
	return ret, nil
}

// SegwitAddrDecode decodes Segwit Address(string), returns hrp(human-readable part), version(int) and data(bytes array) / or error
func SegwitAddrDecode(addr string) (string, int, []byte, error) {
	dechrp, data, enc, err := Decode(addr)
	if err != nil {
		return "", -1, nil, err
	}
	if len(data) == 0 || len(data) > 65 {
		return "", -1, nil, errors.Errorf("invalid len(data): %d", len(data))
	}
	if data[0] > 16 {
		return "", -1, nil, errors.Errorf("invalid witness version: %d", data[0])
	}
	if data[0] == 0 && enc != EncodingBech32 {
		return "", -1, nil, errors.Errorf("%d != EncodingBech32", enc)
	}
	if data[0] > 0 && enc != EncodingBech32m {
		return "", -1, nil, errors.Errorf("%d != EncodingBech32m", enc)
	}
	res, err := convertbits(data[1:], 5, 8, false)
	if err != nil {
		return "", -1, nil, err
	}
	if len(res) < 2 || len(res) > 40 {
		return "", -1, nil, errors.Errorf("invalid convertbits length: %d", len(res))
	}
	if data[0] == 0 && len(res) != 20 && len(res) != 32 {
		return "", -1, nil, errors.Errorf("invalid program length for witness version 0 (per BIP141): %d", len(res))
	}
	return dechrp, int(data[0]), res, nil
}

// SegwitAddrEncode encodes hrp(human-readable part) , version(int) and data(bytes array), returns Segwit Address / or error
func SegwitAddrEncode(hrp string, version int, program []byte) (string, error) {
	if version < 0 || version > 16 {
		return "", errors.Errorf("invalid witness version : %d", version)
	}
	if len(program) < 2 || len(program) > 40 {
		return "", errors.Errorf("invalid program length : %d", len(program))
	}
	if version == 0 && len(program) != 20 && len(program) != 32 {
		return "", errors.Errorf("invalid program length for witness version 0 (per BIP141) : %d", len(program))
	}
	data, err := convertbits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	enc := EncodingBech32
	if version > 0 {
		enc = EncodingBech32m
	}
	ret, err := Encode(hrp, append([]byte{byte(version)}, data...), enc)
	if err != nil {
		return "", errors.Wrap(err, "")
	}
	return ret, nil
}

func SegwitScriptPubKey(witver int, witprog []byte) []byte {
	var opcode byte
	if witver != 0 {
		opcode = byte(0x50 + witver)
	} else {
		opcode = 0
	}

	instrcs := []script.Instruction{
		{Opcode: opcode},
		{Data: witprog},
	}
	return script.Encode(instrcs)
}

func finalConstant(enc Encoding) uint32 {
	switch enc {
	case EncodingBech32:
		return 1
	case EncodingBech32m:
		return 0x2bc830a3
	default:
		panic("unknown encoding")
	}
}
