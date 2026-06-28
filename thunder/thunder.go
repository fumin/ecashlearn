package thunder

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/fumin/ecashlearn/bech32"
	"github.com/fumin/ecashlearn/bitcoin"
	"github.com/fumin/ecashlearn/enforcer/types"
	"github.com/fumin/ecashlearn/util"
	"github.com/fumin/ecashlearn/util/bincode"
	"github.com/fumin/ecashlearn/util/borsh"
	"github.com/pkg/errors"
	"github.com/tyler-smith/go-bip39"
	"github.com/zeebo/blake3"
)

const (
	thisSidechain = 9

	dbHeaders           = "headers"
	dbBodies            = "bodies"
	dbWithdrawalBundles = "withdrawal_bundles"
	dbTip               = "tip"
	dbHeight            = "height"

	blake3Length = 32
)

type Hash = [blake3Length]byte
type MerkleRoot = Hash
type BlockHash = Hash
type Address = [20]byte

type ContentWithdrawal struct {
	Value       bitcoin.Amount
	MainFee     bitcoin.Amount
	MainAddress []byte
}

type Content struct {
	Enum       bincode.Enum `borsh_enum:"true"`
	Value      bitcoin.Amount
	Withdrawal ContentWithdrawal
}

type Output struct {
	Address Address
	Content Content
}

type TxID = Hash

type OutPointRegular struct {
	TxID TxID
	Vout uint32
}

type OutPointCoinbase struct {
	MerkleRoot MerkleRoot
	Vout       uint32
}

type OutPoint struct {
	Enum     bincode.Enum `borsh_enum:"true"`
	Regular  OutPointRegular
	Coinbase OutPointCoinbase
	Deposit  bitcoin.Outpoint
}

type OutPointHash struct {
	OutPoint OutPoint
	Hash     Hash
}

type Proof struct {
	Targets []uint64
	Hashes  []BitcoinNodeHash
}

type Transaction struct {
	Input  []OutPointHash
	Proof  Proof
	Output []Output
}

func (t Transaction) ID() []byte {
	type OutPointDeposit OutPointRegular
	type BOutPoint struct {
		Enum     borsh.Enum `borsh_enum:"true"`
		Regular  OutPointRegular
		Coinbase OutPointCoinbase
		Deposit  OutPointDeposit
	}
	type BOutPointHash struct {
		OutPoint BOutPoint
		Hash     Hash
	}
	type BContent struct {
		Enum       borsh.Enum `borsh_enum:"true"`
		Value      bitcoin.Amount
		Withdrawal ContentWithdrawal
	}
	type BOutput struct {
		Address Address
		Content BContent
	}
	type BTransaction struct {
		Input  []BOutPointHash
		Output []BOutput
	}

	var bt BTransaction
	for _, input := range t.Input {
		txid := input.OutPoint.Deposit.TxID[:]
		slices.Reverse(txid)

		bi := BOutPointHash{
			OutPoint: BOutPoint{
				Enum:     borsh.Enum(input.OutPoint.Enum),
				Regular:  input.OutPoint.Regular,
				Coinbase: input.OutPoint.Coinbase,
				Deposit: OutPointDeposit{
					TxID: TxID(txid),
					Vout: input.OutPoint.Deposit.Vout,
				},
			},
			Hash: input.Hash,
		}
		bt.Input = append(bt.Input, bi)
	}
	for i, output := range t.Output {
		var spk []byte
		if output.Content.Enum == 1 {
			mainAddr := output.Content.Withdrawal.MainAddress
			_, witver, witprog, err := bech32.SegwitAddrDecode(string(mainAddr))
			if err != nil {
				panic(fmt.Sprintf("%d %+v", i, err))
			}
			spk = bech32.SegwitScriptPubKey(witver, witprog)
		}

		bo := BOutput{
			Address: output.Address,
			Content: BContent{
				Enum:  borsh.Enum(output.Content.Enum),
				Value: output.Content.Value,
				Withdrawal: ContentWithdrawal{
					Value:       output.Content.Withdrawal.Value,
					MainFee:     output.Content.Withdrawal.MainFee,
					MainAddress: spk,
				},
			},
		}
		bt.Output = append(bt.Output, bo)
	}

	b0, err := borsh.Serialize(bt)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	b1 := blake3.Sum256(b0)
	return b1[:]
}

type Signature struct {
	R [32]byte
	S [32]byte
}

type Authorization struct {
	VerifyingKey []byte
	Signature    Signature
}

type Body struct {
	Coinbase       []Output
	Transactions   []Transaction
	Authorizations []Authorization
}

func getBlockBody(dbPath string, blockHash []byte) (Body, error) {
	b, err := util.Get(dbPath, dbBodies, blockHash)
	if err != nil {
		return Body{}, errors.Wrap(err, "")
	}
	var body Body
	if err := bincode.Deserialize(&body, b); err != nil {
		return Body{}, errors.Wrap(err, "")
	}

	// Reverse bytes according to convention.
	for _, tx := range body.Transactions {
		for _, input := range tx.Input {
			slices.Reverse(input.OutPoint.Deposit.TxID)
		}
	}

	return body, nil
}

type BitcoinNodeHash struct {
	Enum        bincode.Enum `borsh_enum:"true"`
	Empty       struct{}
	Placeholder struct{}
	Some        [32]byte
}

type Header struct {
	MerkleRoot   MerkleRoot
	PrevSideHash *BlockHash
	PrevMainHash []byte
	Roots        []BitcoinNodeHash
}

func getBlockHeader(dbPath string, blockHash []byte) (Header, error) {
	hb, err := util.Get(dbPath, dbHeaders, blockHash)
	if err != nil {
		return Header{}, errors.Wrap(err, "")
	}
	var header Header
	if err := bincode.Deserialize(&header, hb); err != nil {
		return Header{}, errors.Wrap(err, "")
	}
	slices.Reverse(header.PrevMainHash)
	return header, nil
}

func getTip(dbPath string) ([]byte, error) {
	contents, err := util.ScanDB(dbPath, dbTip)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return contents[0].V, nil
}

func getHeight(dbPath string) (int, error) {
	contents, err := util.ScanDB(dbPath, dbHeight)
	if err != nil {
		return -1, errors.Wrap(err, "")
	}
	hb := contents[0].V
	height := binary.LittleEndian.Uint32(hb)
	return int(height), nil
}

type OutPointPut struct {
	OutPoint OutPoint
	Output   Output
}

type WithdrawalBundle struct {
	SpendUtxos []OutPointPut
	Tx         bitcoin.Transaction
}

type WithdrawalBundleInfo struct {
	Enum             bincode.Enum `borsh_enum:"true"`
	Known            WithdrawalBundle
	Unknown          struct{}
	UnknownConfirmed []OutPointPut
}

type RollBack[T any] struct {
	Value  T
	Height uint32
}

type WithdrawalBundleStatus struct {
	Enum                bincode.Enum `borsh_enum:"true"`
	Confirmed           struct{}
	Dropped             struct{}
	Failed              struct{}
	Pending             struct{}
	Submitted           struct{}
	SubmittedUnexpected struct{}
}

type WithdrawalBundleIS struct {
	Info   WithdrawalBundleInfo
	Status []RollBack[WithdrawalBundleStatus]
}

func getWithdrawalBundle(dbPath string, m6id types.M6ID) (WithdrawalBundleIS, error) {
	m6idB, err := bincode.Serialize(m6id)
	if err != nil {
		return WithdrawalBundleIS{}, errors.Wrap(err, "")
	}
	b, err := util.Get(dbPath, dbWithdrawalBundles, m6idB)
	if err != nil {
		return WithdrawalBundleIS{}, errors.Wrap(err, "")
	}
	var v WithdrawalBundleIS
	if err := bincode.Deserialize(&v, b); err != nil {
		return WithdrawalBundleIS{}, errors.Wrap(err, "")
	}

	return v, nil
}

func formatForDeposit(mnemonic string, index int) (string, error) {
	addr, err := GetAddress(mnemonic, index)
	if err != nil {
		return "", errors.Wrap(err, "")
	}
	ab58 := util.Base58.EncodeToString(addr)

	prefix := fmt.Sprintf("s%d_%s_", thisSidechain, ab58)
	prefixDigest := sha256.Sum256([]byte(prefix))
	checksum := hex.EncodeToString(prefixDigest[:3])

	return prefix + checksum, nil
}

func GetAddress(mnemonic string, index int) ([]byte, error) {
	const passphrase = ""
	seed := bip39.NewSeed(mnemonic, passphrase)
	master := NewMasterKey(seed)
	privKey, err := master.DerivePath(fmt.Sprintf("m/1'/0'/0'/%d'", index))
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	b3 := blake3.Sum512(privKey.PublicKey())
	return b3[:20], nil
}
