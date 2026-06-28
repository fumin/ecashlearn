package thunder

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"slices"
	"testing"

	"github.com/fumin/ecashlearn/bech32"
	"github.com/fumin/ecashlearn/bip380"
	"github.com/fumin/ecashlearn/bitcoin"
	"github.com/fumin/ecashlearn/crypto"
	"github.com/fumin/ecashlearn/enforcer/types"
	"github.com/fumin/ecashlearn/script"
	"github.com/fumin/ecashlearn/util"
	"github.com/fumin/ecashlearn/util/bincode"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func TestWithdrawalBundles(t *testing.T) {
	dbPath := "../testdata/thunder/data.mdb"
	tests := []struct {
		m6id       types.M6ID
		withdrawal WithdrawalBundleIS
	}{
		{
			m6id: util.HexD("163f404a5a4ab144638393d4f2a541641d834cd50bf174e7e32120e620558960"),
			withdrawal: WithdrawalBundleIS{
				Info: WithdrawalBundleInfo{
					Enum: 0,
					Known: WithdrawalBundle{
						SpendUtxos: []OutPointPut{
							{
								OutPoint: OutPoint{
									Enum: 0,
									Regular: OutPointRegular{
										TxID: TxID(util.HexD("708fb77450933cb69222ea57380c1fbe7fb1dd46215248e6837533ff93b42e12")),
										Vout: 0,
									},
								},
								Output: Output{
									Address: Address(l2Addr("side art direct sausage exit worry minor stomach size zero dinner buzz", 4)),
									Content: Content{
										Enum: 1,
										Withdrawal: ContentWithdrawal{
											Value:       1000000,
											MainFee:     10000,
											MainAddress: []byte(l1Addr("leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor", "", "m/84'/1'/0'/1/2", bech32.HumanReadablePartTestnet)),
										},
									},
								},
							},
						},
						Tx: bitcoin.Transaction{
							Version:  2,
							LockTime: 0,
							Output: []bitcoin.TxOut{
								{
									Amount: 0,
									Script: script.Encode([]script.Instruction{
										{Opcode: script.OP_RETURN},
										// WithdrawalBundle's mainchain_fee_txout is in big endian.
										// https://github.com/LayerTwo-Labs/thunder-rust/blob/9beaf02ad45a55ac4a6c43317ee333271ceb209d/lib/types/mod.rs#L359
										{Data: binary.BigEndian.AppendUint64(nil, 10000)},
									}),
								},
								{
									Amount: 0,
									Script: script.Encode([]script.Instruction{
										{Opcode: script.OP_RETURN},
										{Data: util.HexD("0e44d75eb4b9af58b845557ce71a20de53b78827a2373d103d656b52e5430628")},
									}),
								},
								{
									Amount: 1000000,
									Script: script.Encode([]script.Instruction{
										{Opcode: script.OP_0},
										{Data: crypto.Hash160(l1PrivKey("leisure absorb unfair bunker focus absorb hire famous hurdle describe true monitor", "", "m/84'/1'/0'/1/2").PublicKey().Key)},
									}),
								},
							},
						},
					},
				},
				Status: []RollBack[WithdrawalBundleStatus]{
					{
						Value:  WithdrawalBundleStatus{Enum: 3},
						Height: 255,
					},
					{
						Value:  WithdrawalBundleStatus{Enum: 4},
						Height: 257,
					},
					{
						Value:  WithdrawalBundleStatus{Enum: 0},
						Height: 263,
					},
				},
			},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			w, err := getWithdrawalBundle(dbPath, test.m6id)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if err := util.JsonEq(w, test.withdrawal); err != nil {
				t.Errorf("%+v", err)
			}
		})
	}
}

func TestChain(t *testing.T) {
	dbPath := "../testdata/thunder/data.mdb"
	tests := []struct {
		blockHash []byte
		header    Header
		body      Body
	}{
		{
			blockHash: util.HexD("3d6e356511f5aac89dbb6d051eb234e8c05e24740ac9e3dec2fe55c90a4aac39"),
			header: Header{
				MerkleRoot:   MerkleRoot(util.HexD("ad609aab58365210a611957240b55acd776b2a8a2ff45ddd1799af22246b1f1d")),
				PrevSideHash: hexD32P("d25d300271b55f777aacfa3da755d0ae1edbcc88488885b8f4f54790c1edc389"),
				PrevMainHash: util.HexD("0000022bdf20bf4894e48a563172d57cf60ff1072ed1f6f9720a579ea0bf61a5"),
				Roots: []BitcoinNodeHash{
					{Some: [32]byte{167, 234, 119, 32, 23, 134, 125, 120, 232, 7, 38, 53, 132, 149, 104, 15, 247, 9, 49, 37, 170, 126, 124, 10, 158, 202, 153, 27, 17, 210, 85, 151}, Enum: 2},
					{Some: [32]byte{151, 201, 74, 206, 92, 157, 214, 55, 255, 158, 126, 221, 22, 219, 230, 237, 171, 129, 66, 107, 14, 34, 0, 112, 246, 107, 250, 211, 210, 55, 192, 97}, Enum: 2},
					{Some: [32]byte{97, 60, 143, 224, 148, 7, 193, 115, 192, 53, 174, 216, 138, 126, 214, 87, 146, 105, 4, 179, 51, 236, 234, 61, 18, 74, 28, 94, 32, 222, 85, 116}, Enum: 2},
					{Some: [32]byte{253, 173, 1, 82, 129, 107, 2, 212, 193, 17, 243, 51, 3, 93, 136, 74, 253, 67, 178, 128, 24, 28, 141, 229, 219, 240, 214, 246, 6, 2, 67, 188}, Enum: 2},
				},
			},
		},
		{
			blockHash: util.HexD("b2801de2dacdec717a27f793dc1bf9510ea3c21124c025e0ec1f3a24762d5788"),
			header: Header{
				MerkleRoot:   MerkleRoot(util.HexD("92b35a109d70066d29eb80838a9106f29a0550e532780d9f6756c1fb206732a4")),
				PrevSideHash: hexD32P("a60e5c2b6058206f289a9d4ee4ba919ad9e93efb728ada287b180da1b157160f"),
				PrevMainHash: util.HexD("000001818125c165d4333e724b74911e9b89a7736e0b192e64408203f11ed032"),
				Roots: []BitcoinNodeHash{
					{Some: [32]byte{167, 234, 119, 32, 23, 134, 125, 120, 232, 7, 38, 53, 132, 149, 104, 15, 247, 9, 49, 37, 170, 126, 124, 10, 158, 202, 153, 27, 17, 210, 85, 151}, Enum: 2},
					{Some: [32]byte{151, 201, 74, 206, 92, 157, 214, 55, 255, 158, 126, 221, 22, 219, 230, 237, 171, 129, 66, 107, 14, 34, 0, 112, 246, 107, 250, 211, 210, 55, 192, 97}, Enum: 2},
					{Some: [32]byte{141, 131, 85, 76, 162, 203, 1, 228, 200, 166, 89, 154, 60, 244, 210, 117, 240, 40, 21, 117, 2, 28, 163, 23, 41, 243, 11, 148, 14, 121, 172, 1}, Enum: 2},
					{Some: [32]byte{253, 173, 1, 82, 129, 107, 2, 212, 193, 17, 243, 51, 3, 93, 136, 74, 253, 67, 178, 128, 24, 28, 141, 229, 219, 240, 214, 246, 6, 2, 67, 188}, Enum: 2},
				},
			},
			body: Body{
				Coinbase: []Output{
					{
						Address: Address(util.Base58D("46sGhkMQxM8628izz9CRgpbRMM8B")),

						Content: Content{Value: 10000, Enum: 0},
					},
				},
				Transactions: []Transaction{
					{
						Input: []OutPointHash{
							{
								OutPoint: OutPoint{
									Deposit: bitcoin.Outpoint{
										TxID: util.HexD("42f1cdbf2e90a8b045fc8df1c76076f23f0b8909c4fda715e76b2f8bb6002a62"),
										Vout: 0},
									Enum: 2},
								Hash: Hash{222, 204, 46, 150, 125, 173, 38, 84, 18, 38, 167, 116, 44, 73, 124, 101, 31, 169, 111, 48, 4, 241, 120, 247, 235, 11, 220, 173, 171, 247, 107, 217},
							},
						},
						Proof: Proof{
							Targets: []uint64{10},
							Hashes: []BitcoinNodeHash{
								{Some: [32]byte{16, 137, 135, 15, 52, 115, 201, 27, 74, 222, 111, 160, 90, 193, 187, 239, 210, 223, 156, 204, 186, 176, 87, 29, 90, 170, 92, 77, 57, 137, 233, 219}, Enum: 2},
								{Some: [32]byte{66, 215, 192, 224, 206, 91, 92, 200, 234, 244, 23, 71, 248, 96, 3, 29, 23, 159, 241, 136, 65, 47, 244, 189, 29, 244, 170, 97, 33, 218, 238, 19}, Enum: 2},
							},
						},
						Output: []Output{
							{
								Address: Address(l2Addr("side art direct sausage exit worry minor stomach size zero dinner buzz", 4)),
								Content: Content{
									Withdrawal: ContentWithdrawal{
										Value:       1000000,
										MainFee:     10000,
										MainAddress: []byte("tb1qcjvzx05mhehg7nk0q8sevxmh747ez9thzn42vy"),
									},
									Enum: 1},
							},
							{
								Address: Address(l2Addr("side art direct sausage exit worry minor stomach size zero dinner buzz", 5)),
								Content: Content{Value: 1990000, Enum: 0},
							},
						},
					},
				},
				Authorizations: []Authorization{
					{
						VerifyingKey: []byte{113, 140, 137, 98, 77, 253, 139, 231, 233, 153, 27, 26, 89, 47, 189, 93, 242, 44, 246, 152, 46, 78, 209, 122, 95, 127, 227, 226, 86, 164, 116, 171},
						Signature: Signature{
							R: [32]byte{183, 249, 81, 186, 196, 182, 219, 143, 114, 26, 123, 229, 29, 135, 72, 6, 103, 193, 224, 156, 118, 57, 219, 92, 142, 228, 58, 215, 125, 130, 123, 167},
							S: [32]byte{177, 140, 125, 201, 210, 59, 107, 141, 175, 229, 111, 233, 142, 61, 137, 88, 0, 221, 56, 234, 181, 215, 171, 133, 41, 141, 148, 147, 212, 119, 148, 4},
						},
					},
				},
			},
		},
		{
			blockHash: util.HexD("4970b5c50448d9dd70e2837cef8130a0eb7651bc0ac285e4c3fbd96887fb18df"),
			header: Header{
				MerkleRoot:   MerkleRoot(util.HexD("49f6ae0fe4b880f858b46e4148f33eca581784153bec51f380fc094ec803bc56")),
				PrevSideHash: hexD32P("f8eb5090e7a69c5d283254a8f62452e8aaf3ec33225a9bb89a0c3f09822df3a8"),
				PrevMainHash: util.HexD("000000c49b3534491dc1ccaa0196e3dd201fab5c83e7061efc7148884405010d"),
				Roots: []BitcoinNodeHash{
					{Some: [32]byte{3, 30, 205, 86, 199, 181, 52, 87, 159, 154, 208, 11, 22, 251, 192, 98, 60, 160, 20, 92, 245, 215, 127, 150, 98, 215, 105, 184, 162, 84, 41, 4}, Enum: 2},
					{Some: [32]byte{73, 135, 30, 209, 43, 45, 113, 101, 232, 248, 19, 210, 218, 1, 174, 198, 35, 46, 216, 180, 126, 226, 239, 48, 245, 162, 254, 62, 114, 44, 65, 129}, Enum: 2},
				},
			},
			body: Body{
				Coinbase: []Output{
					{
						Address: Address(util.Base58D("3Bsmphk8pL56aCV7UaKxdNYFPzYC")),
						Content: Content{Value: 10000, Enum: 0},
					},
				},
				Transactions: []Transaction{
					{
						Input: []OutPointHash{
							{
								OutPoint: OutPoint{
									Deposit: bitcoin.Outpoint{
										TxID: util.HexD("18a3f734ce92ebcd8de701a70908b167062a63f77e717f4d4a6e2c225544110c"),
										Vout: 0},
									Enum: 2},
								Hash: Hash{186, 186, 105, 68, 127, 100, 55, 246, 43, 216, 13, 103, 64, 172, 144, 210, 229, 4, 84, 70, 170, 153, 111, 183, 47, 166, 127, 245, 195, 161, 167, 60},
							},
						},
						Proof: Proof{
							Targets: []uint64{1},
							Hashes: []BitcoinNodeHash{
								{Some: [32]byte{193, 57, 184, 244, 163, 10, 65, 38, 92, 167, 217, 24, 1, 25, 8, 197, 170, 109, 36, 152, 13, 95, 254, 182, 218, 65, 229, 128, 156, 33, 38, 253}, Enum: 2},
								{Some: [32]byte{133, 144, 82, 161, 154, 89, 97, 182, 209, 59, 7, 254, 118, 254, 114, 131, 142, 121, 253, 204, 86, 175, 216, 82, 102, 121, 174, 69, 195, 158, 93, 25}, Enum: 2},
							},
						},
						Output: []Output{
							{
								Address: Address(util.Base58D("2VLxEHqGFuvm789yKGN2bAPZrSzi")),
								Content: Content{
									Withdrawal: ContentWithdrawal{
										Value:       20980000,
										MainFee:     10000,
										MainAddress: []byte("tb1qjgpuv95wzqn5zfvmvzllkfn4ww6tlwk5afmuna"),
									},
									Enum: 1},
							},
							{
								Address: Address(util.Base58D("3nJdAwBwZzuHrQhPABAM98nhGxNt")),
								Content: Content{Value: 10000, Enum: 0},
							},
						},
					},
				},
				Authorizations: []Authorization{
					{
						VerifyingKey: []byte{88, 100, 160, 116, 41, 65, 153, 19, 25, 76, 23, 215, 255, 192, 122, 244, 53, 102, 12, 247, 226, 189, 211, 64, 23, 173, 0, 86, 113, 21, 25, 244},
						Signature: Signature{
							R: [32]byte{119, 255, 9, 204, 3, 21, 140, 43, 13, 71, 204, 64, 234, 124, 65, 138, 55, 113, 214, 84, 234, 20, 124, 89, 13, 190, 40, 159, 121, 25, 252, 114},
							S: [32]byte{13, 17, 25, 132, 98, 109, 152, 195, 192, 91, 132, 65, 19, 147, 6, 63, 201, 21, 91, 145, 35, 170, 182, 23, 56, 255, 116, 68, 86, 3, 23, 1},
						},
					},
				},
			},
		},
		{
			blockHash: util.HexD("19bf0990a4fa4ffce101700d09e28aa23e6b8a64903f4c30e2b7dbdc74a695bf"),
			header: Header{
				MerkleRoot:   MerkleRoot(util.HexD("36bc41debfae85b97ba661871fac44b3472fd189898c4412177bf665cd10079d")),
				PrevSideHash: hexD32P("33783b8d91d02e9de66ebb98bd9a810f81025212c37014738c9bbbb21cc5d714"),
				PrevMainHash: util.HexD("0000029f1bee3ef7aa3ddc49bb48de90b14c6a352aaa1516849479ad8a8b1493"),
				Roots: []BitcoinNodeHash{
					{Some: [32]byte{182, 73, 107, 136, 226, 105, 103, 253, 176, 106, 252, 116, 34, 245, 218, 70, 187, 100, 15, 94, 214, 48, 227, 37, 152, 103, 20, 94, 232, 116, 94, 85}, Enum: 2},
					{Some: [32]byte{3, 220, 230, 144, 139, 17, 101, 159, 171, 20, 200, 130, 3, 234, 12, 213, 67, 47, 134, 114, 240, 156, 172, 244, 26, 201, 162, 88, 138, 117, 125, 146}, Enum: 2},
				},
			},
			body: Body{
				Coinbase: []Output{
					{
						Address: Address(util.Base58D("2wKabCMgX8wjfHm8sLJKRTixxCyS")),
						Content: Content{Value: 1000, Enum: 0},
					},
				},
				Transactions: []Transaction{
					{
						Input: []OutPointHash{
							{
								OutPoint: OutPoint{
									Deposit: bitcoin.Outpoint{
										TxID: util.HexD("b8764aadd0bce5222081c60a2fd8bed6ee5353d5e852dd1258c34a5220623415"),
										Vout: 0},
									Enum: 2},
								Hash: Hash{171, 146, 67, 170, 26, 231, 143, 235, 121, 14, 44, 2, 94, 13, 72, 114, 23, 249, 9, 91, 201, 5, 38, 209, 228, 153, 216, 159, 160, 238, 172, 200},
							},
						},
						Proof: Proof{
							Targets: []uint64{2},
							Hashes:  nil,
						},
						Output: []Output{
							{
								Address: Address(util.Base58D("37BAmjpwm7MVxpKWxmh858kT4DZE")),
								Content: Content{
									Withdrawal: ContentWithdrawal{
										Value:       3000000,
										MainFee:     10000,
										MainAddress: []byte("tb1q3ytwzhc9hk6g7twrkfmr5wfhgc9jrwhw0v4nnc"),
									},
									Enum: 1},
							},
							{
								Address: Address(util.Base58D("2MUHsqM4jF4NLJFQ62h6ATLjsu4B")),
								Content: Content{Value: 999000, Enum: 0},
							},
						},
					},
				},
				Authorizations: []Authorization{
					{
						VerifyingKey: []byte{38, 103, 33, 110, 145, 33, 216, 128, 92, 218, 122, 105, 187, 44, 208, 114, 182, 52, 116, 208, 126, 167, 166, 226, 174, 74, 223, 137, 122, 243, 203, 226},
						Signature: Signature{
							R: [32]byte{61, 197, 1, 81, 198, 95, 203, 10, 81, 201, 58, 250, 200, 222, 238, 210, 191, 81, 204, 116, 196, 130, 150, 236, 102, 111, 213, 97, 114, 60, 236, 44},
							S: [32]byte{91, 8, 49, 154, 245, 232, 144, 143, 235, 82, 109, 112, 75, 185, 91, 57, 82, 8, 82, 49, 83, 118, 10, 171, 164, 17, 201, 133, 169, 80, 43, 1},
						},
					},
				},
			},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			// Check header.
			header, err := getBlockHeader(dbPath, test.blockHash)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if err := util.JsonEq(header, test.header); err != nil {
				t.Errorf("%+v", err)
			}

			// Check header serialization.
			hb, err := util.Get(dbPath, "headers", test.blockHash)
			if err != nil {
				t.Errorf("%+v", err)
			}
			slices.Reverse(header.PrevMainHash)
			headerB, err := bincode.Serialize(header)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if !bytes.Equal(hb, headerB) {
				t.Errorf("%x != %x", hb, headerB)
			}

			// Check body.
			body, err := getBlockBody(dbPath, test.blockHash)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if err := util.JsonEq(body, test.body); err != nil {
				t.Errorf("%+v", err)
			}
		})
	}
}

func TestHeightTip(t *testing.T) {
	dbPath := "../testdata/thunder/data.mdb"
	height, err := getHeight(dbPath)
	if err != nil {
		t.Errorf("%+v", err)
	}
	heightWant := 325
	if height != heightWant {
		t.Errorf("%d != %d", height, heightWant)
	}

	tip, err := getTip(dbPath)
	if err != nil {
		t.Errorf("%+v", err)
	}
	tipWant := "3d6e356511f5aac89dbb6d051eb234e8c05e24740ac9e3dec2fe55c90a4aac39"
	if tipH := hex.EncodeToString(tip); tipH != tipWant {
		t.Errorf("%s != %s", tipH, tipWant)
	}
}

func TestFormatForDeposit(t *testing.T) {
	tests := []struct {
		mnemonic      string
		index         int
		bitwindowAddr string
	}{
		{
			mnemonic:      "side art direct sausage exit worry minor stomach size zero dinner buzz",
			index:         3,
			bitwindowAddr: "s9_3erUndZkE7jNkCfsLAgTcmGQ2Qxd_5d4f31",
		},
		{
			mnemonic:      "side art direct sausage exit worry minor stomach size zero dinner buzz",
			index:         5,
			bitwindowAddr: "s9_eip9xtQvBJKtQ5XVdnkHFpMbn1R_468468",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			bwAddr, err := formatForDeposit(test.mnemonic, test.index)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if bwAddr != test.bitwindowAddr {
				t.Errorf("formatForDeposit(%s, %d) = %s want %s", test.mnemonic, test.index, bwAddr, test.bitwindowAddr)
			}
		})
	}
}

func TestGetAddress(t *testing.T) {
	tests := []struct {
		mnemonic string
		index    int
		address  string
	}{
		{
			mnemonic: "side art direct sausage exit worry minor stomach size zero dinner buzz",
			index:    1,
			address:  "5e130565a060008efb5da22f41bd966d9a4c878c",
		},
		{
			mnemonic: "side art direct sausage exit worry minor stomach size zero dinner buzz",
			index:    2,
			address:  "18b85623e06c7475723014eeec6b85facf923a56",
		},
		{
			mnemonic: "side art direct sausage exit worry minor stomach size zero dinner buzz",
			index:    3,
			address:  "be674579cd6410d13af38f7e1a26d107fce1944e",
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			addr, err := GetAddress(test.mnemonic, test.index)
			if err != nil {
				t.Errorf("%+v", err)
			}
			if ah := hex.EncodeToString(addr); ah != test.address {
				t.Errorf("GetAddress(%s, %d) = %s want %s", test.mnemonic, test.index, ah, test.address)
			}
		})
	}
}

func TestThunderWalletSeed(t *testing.T) {
	mnemonic := "side art direct sausage exit worry minor stomach size zero dinner buzz"
	passphrase := ""
	mnemonicSeed := bip39.NewSeed(mnemonic, passphrase)
	walletPath := "../testdata/thunder/wallet.mdb"
	contents, err := util.ScanDB(walletPath, "seed")
	if err != nil {
		t.Errorf("%+v", err)
	}
	walletSeed := contents[0].V
	if !bytes.Equal(walletSeed, mnemonicSeed) {
		t.Errorf("%x != %x", walletSeed, mnemonicSeed)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds | log.Llongfile | log.LstdFlags)

	m.Run()
}

func hexD32P(s string) *[32]byte {
	b := [32]byte(util.HexD(s))
	return &b
}

func l1PrivKey(mnemonic, passphrase, derivationPath string) *bip32.Key {
	privKey, _, err := bip380.WpkhAddress(mnemonic, passphrase, derivationPath, "unused")
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	return privKey
}

func l1Addr(mnemonic, passphrase, derivationPath, humanReadablePart string) string {
	_, addr, err := bip380.WpkhAddress(mnemonic, passphrase, derivationPath, humanReadablePart)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	return addr
}

func l2Addr(mnemonic string, index int) []byte {
	addr, err := GetAddress(mnemonic, index)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	return addr
}
