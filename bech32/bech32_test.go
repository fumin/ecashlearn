package bech32

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestValidChecksum(t *testing.T) {
	validChecksums := []string{
		"A12UEL5L",
		"a12uel5l",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
		"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
		"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
		"?1ezyfcl",
	}
	for _, validChecksum := range validChecksums {
		t.Run(validChecksum, func(t *testing.T) {
			hrp, data, enc, err := Decode(validChecksum)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if enc != EncodingBech32 {
				t.Errorf("%v != EncodingBech32", enc)
			}
			rebuild, err := Encode(hrp, data, enc)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if lvc := strings.ToLower(validChecksum); rebuild != lvc {
				t.Errorf("%s != %s", rebuild, lvc)
			}
		})
	}
}

func TestInvalidChecksum(t *testing.T) {
	invalidChecksums := []string{
		" 1nwldj5",
		"\x7f" + "1axkwrx",
		"\x80" + "1eym55h",
		"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
		"pzry9x0s0muk",
		"1pzry9x0s0muk",
		"x1b4n0q5v",
		"li1dgmt3",
		"de1lg7wt\xff",
		"A1G7SGD8",
		"10a06t8",
		"1qzzfhee",
	}
	for _, invalidChecksum := range invalidChecksums {
		t.Run(invalidChecksum, func(t *testing.T) {
			_, _, _, err := Decode(invalidChecksum)
			if err == nil {
				t.Errorf("Decode(%s) should fail", invalidChecksum)
			}
		})
	}
}

func TestValidChecksumBech32m(t *testing.T) {
	validChecksums := []string{
		"A1LQFN3A",
		"a1lqfn3a",
		"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
		"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
		"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
		"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
		"?1v759aa",
	}
	for _, validChecksum := range validChecksums {
		t.Run(validChecksum, func(t *testing.T) {
			hrp, data, enc, err := Decode(validChecksum)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if enc != EncodingBech32m {
				t.Errorf("%v != EncodingBech32m", enc)
			}
			rebuild, err := Encode(hrp, data, enc)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if lvc := strings.ToLower(validChecksum); rebuild != lvc {
				t.Errorf("%s != %s", rebuild, lvc)
			}
		})
	}
}

func TestInvalidChecksumBech32m(t *testing.T) {
	invalidChecksums := []string{
		" 1xj0phk",
		"\x7F" + "1g6xzxy",
		"\x80" + "1vctc34",
		"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
		"qyrz8wqd2c9m",
		"1qyrz8wqd2c9m",
		"y1b0jsk6g",
		"lt1igcx5c0",
		"in1muywd",
		"mm1crxm3i",
		"au1s5cgom",
		"M1VUXWEZ",
		"16plkw9",
		"1p2gdwpf",
	}
	for _, invalidChecksum := range invalidChecksums {
		t.Run(invalidChecksum, func(t *testing.T) {
			_, _, _, err := Decode(invalidChecksum)
			if err == nil {
				t.Errorf("Decode(%s) should fail", invalidChecksum)
			}
		})
	}
}

func TestValidAddress(t *testing.T) {
	tests := []struct {
		address      string
		scriptPubKey []byte
	}{
		{
			address: "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
			scriptPubKey: []byte{
				0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
				0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6},
		},
		{
			address: "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
			scriptPubKey: []byte{
				0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
				0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
				0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
				0x62},
		},
		{
			address: "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
			scriptPubKey: []byte{
				0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
				0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
				0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
				0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6},
		},
		{
			address:      "BC1SW50QGDZ25J",
			scriptPubKey: []byte{0x60, 0x02, 0x75, 0x1e},
		},
		{
			address: "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
			scriptPubKey: []byte{
				0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
				0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23},
		},
		{
			address: "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
			scriptPubKey: []byte{
				0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
				0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
				0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
				0x33},
		},
		{
			address: "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
			scriptPubKey: []byte{
				0x51, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
				0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
				0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
				0x33},
		},
		{
			address: "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
			scriptPubKey: []byte{
				0x51, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55,
				0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb,
				0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
				0x98},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			hrp := HumanReadablePartMainnet
			witver, witprog, err := SegwitAddrDecode(hrp, test.address)
			if err != nil {
				hrp = HumanReadablePartTestnet
				witver, witprog, err = SegwitAddrDecode(hrp, test.address)
			}
			if err != nil {
				t.Errorf("%+v", err)
			}
			spk := SegwitScriptPubKey(witver, witprog)
			if !bytes.Equal(spk, test.scriptPubKey) {
				t.Errorf("SegwitScriptPubKey(%d %v) = %v want %v", witver, witprog, spk, test.scriptPubKey)
			}
			rebuild, err := SegwitAddrEncode(hrp, witver, witprog)
			if err != nil {
				t.Errorf("%+v", err)
			}
			la := strings.ToLower(test.address)
			if rebuild != la {
				t.Errorf("%s != %s", rebuild, la)
			}
		})
	}
}

func TestInvalidAddress(t *testing.T) {
	invalidAddresses := []string{
		"tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
		"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
		"tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
		"BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
		"tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
		"bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
		"BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
		"bc1pw5dgrnzv",
		"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
		"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
		"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
		"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
		"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
		"bc1gmk9yu",
	}
	for _, invalidAddress := range invalidAddresses {
		t.Run(invalidAddress, func(t *testing.T) {
			hrp := HumanReadablePartMainnet
			if _, _, err := SegwitAddrDecode(hrp, invalidAddress); err == nil {
				t.Errorf("SegwitAddrDecode(%s, %s) should fail", hrp, invalidAddress)
			}
			hrp = HumanReadablePartTestnet
			if _, _, err := SegwitAddrDecode(hrp, invalidAddress); err == nil {
				t.Errorf("SegwitAddrDecode(%s, %s) should fail", hrp, invalidAddress)
			}
		})
	}
}

func TestInvalidAddressEnc(t *testing.T) {
	tests := []struct {
		hrp           string
		version       int
		programLength int
	}{
		{hrp: "BC", version: 0, programLength: 20},
		{hrp: "bc", version: 0, programLength: 21},
		{hrp: "bc", version: 17, programLength: 32},
		{hrp: "bc", version: 1, programLength: 1},
		{hrp: "bc", version: 16, programLength: 41},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			program := make([]byte, test.programLength)
			if _, err := SegwitAddrEncode(test.hrp, test.version, program); err == nil {
				t.Errorf("SegwitAddrEncode(%s, %d, %v) should fail", test.hrp, test.version, program)
			}
		})
	}
}
