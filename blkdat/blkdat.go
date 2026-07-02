package blkdat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/fumin/ecashlearn/bitcoin"
	"github.com/fumin/ecashlearn/crypto"
	"github.com/fumin/ecashlearn/script"
	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

const (
	SIGHASH_DEFAULT      = 0
	SIGHASH_ALL          = 1
	SIGHASH_NONE         = 2
	SIGHASH_SINGLE       = 3
	SIGHASH_ANYONECANPAY = 0x80
)

type Input struct {
	PrevOut  bitcoin.Outpoint
	Script   []byte
	Sequence []byte
	Witness  [][]byte
}

type Output struct {
	Amount bitcoin.Amount
	Script []byte
}

type Transaction struct {
	Version  uint32
	Marker   byte
	Flag     byte
	Input    []Input
	Output   []Output
	LockTime uint32
}

func (t Transaction) ID() []byte {
	id := make([]byte, 0)
	id = binary.LittleEndian.AppendUint32(id, t.Version)

	id = bitcoin.AppendVarInt(id, len(t.Input))
	for _, inp := range t.Input {
		id = append(id, inp.PrevOut.TxID...)
		id = binary.LittleEndian.AppendUint32(id, inp.PrevOut.Vout)
		id = bitcoin.AppendVarInt(id, len(inp.Script))
		id = append(id, inp.Script...)
		id = append(id, inp.Sequence...)
	}

	id = bitcoin.AppendVarInt(id, len(t.Output))
	for _, out := range t.Output {
		id = binary.LittleEndian.AppendUint64(id, out.Amount)
		id = bitcoin.AppendVarInt(id, len(out.Script))
		id = append(id, out.Script...)
	}
	id = binary.LittleEndian.AppendUint32(id, t.LockTime)

	id = getID(id)
	return id
}

type Header struct {
	Version    []byte
	PrevBlock  []byte
	MerkleRoot []byte
	Time       time.Time
	Target     []byte
	Nonce      []byte
}

type Block struct {
	Size        uint32
	Hash        []byte
	Header      Header
	Transaction []Transaction
}

// Height returns the block height defined in BIP34.
func (blk Block) Height() (int, error) {
	cb := blk.Transaction[0]
	inp := cb.Input[0]
	b := inp.Script
	height, err := parseHeight(b)
	if err != nil {
		return -1, errors.Wrap(err, "")
	}
	return height, nil
}

func parseHeight(b []byte) (int, error) {
	l := int(b[0])
	b = b[1:]
	if len(b) < l {
		return -1, errors.Errorf("%d < %d", len(b), l)
	}
	b = b[:l]

	if 8-len(b) > 0 {
		b = append(b, make([]byte, 8-len(b))...)
	}
	height := binary.LittleEndian.Uint64(b)
	return int(height), nil
}

func Read(fpath, challenge string) ([]Block, error) {
	magic, err := signetMagic(challenge)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	blocks, err := read(fpath, magic)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	return blocks, nil
}

func FindTx(blocks []Block, txIDStr string) (Transaction, error) {
	txID, err := hex.DecodeString(txIDStr)
	if err != nil {
		return Transaction{}, errors.Wrap(err, "")
	}
	for _, b := range blocks {
		for _, tx := range b.Transaction {
			if bytes.Equal(tx.ID(), txID) {
				return tx, nil
			}
		}
	}
	return Transaction{}, errors.Errorf("not found")
}

func parseSignature(signature []byte) (*big.Int, *big.Int, error) {
	r, s := new(big.Int), new(big.Int)
	var inner cryptobyte.String
	input := cryptobyte.String(signature)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) {
		return nil, nil, errors.Errorf("read tag fail")
	}
	if !input.Empty() {
		return nil, nil, errors.Errorf("input not empty")
	}
	if !inner.ReadASN1Integer(r) {
		return nil, nil, errors.Errorf("read r fail")
	}
	if !inner.ReadASN1Integer(s) {
		return nil, nil, errors.Errorf("read s fail")
	}
	if !inner.Empty() {
		return nil, nil, errors.Errorf("inner not empty")
	}
	return r, s, nil
}

// BIP143.
func hashTx(tx Transaction, nIn int, prevOut Output, hashType int) ([]byte, error) {
	txHash := make([]byte, 0)
	txHash = binary.LittleEndian.AppendUint32(txHash, uint32(tx.Version))

	if hashType&SIGHASH_ANYONECANPAY == 0 {
		prevOuts := make([]byte, 0)
		for _, inp := range tx.Input {
			prevOuts = append(prevOuts, inp.PrevOut.TxID...)
			prevOuts = binary.LittleEndian.AppendUint32(prevOuts, inp.PrevOut.Vout)
		}
		prevOutsH := crypto.DoubleSha256(prevOuts)
		txHash = append(txHash, prevOutsH...)
	}

	hashType5 := (hashType & 0x1f) // get last 5 bits since 0x1f = 00011111
	if (hashType&SIGHASH_ANYONECANPAY == 0) && (hashType5 != SIGHASH_SINGLE) && (hashType5 != SIGHASH_NONE) {
		sequences := make([]byte, 0)
		for _, inp := range tx.Input {
			sequences = append(sequences, inp.Sequence...)
		}
		seqH := crypto.DoubleSha256(sequences)
		txHash = append(txHash, seqH...)
	}

	input := tx.Input[nIn]
	txHash = append(txHash, input.PrevOut.TxID...)
	txHash = binary.LittleEndian.AppendUint32(txHash, input.PrevOut.Vout)

	scriptcode, err := p2pkhScript(prevOut.Script)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	txHash = append(txHash, scriptcode...)

	txHash = binary.LittleEndian.AppendUint64(txHash, prevOut.Amount)
	txHash = append(txHash, input.Sequence...)

	outputs := make([]byte, 0)
	if (hashType5 != SIGHASH_SINGLE) && (hashType5 != SIGHASH_NONE) {
		for _, out := range tx.Output {
			outputs = binary.LittleEndian.AppendUint64(outputs, out.Amount)
			outputs = bitcoin.AppendVarInt(outputs, len(out.Script))
			outputs = append(outputs, out.Script...)
		}
	} else if hashType5 == SIGHASH_SINGLE && nIn < len(tx.Output) {
		out := tx.Output[nIn]
		outputs = binary.LittleEndian.AppendUint64(outputs, out.Amount)
		outputs = bitcoin.AppendVarInt(outputs, len(out.Script))
		outputs = append(outputs, out.Script...)
	}
	outH := crypto.DoubleSha256(outputs)
	txHash = append(txHash, outH...)

	txHash = binary.LittleEndian.AppendUint32(txHash, tx.LockTime)
	txHash = binary.LittleEndian.AppendUint32(txHash, uint32(hashType))

	txHash = crypto.DoubleSha256(txHash)
	return txHash, nil
}

func p2pkhScript(segwitScriptPubKey []byte) ([]byte, error) {
	instrcs, err := script.Decode(segwitScriptPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	pubKeyHash := instrcs[1]

	p2pkh := []script.Instruction{
		{Opcode: script.OP_DUP},
		{Opcode: script.OP_HASH160},
		pubKeyHash,
		{Opcode: script.OP_EQUALVERIFY},
		{Opcode: script.OP_CHECKSIG},
	}
	pkhD := script.Encode(p2pkh)

	scriptcode := []script.Instruction{{Data: pkhD}}
	return script.Encode(scriptcode), nil
}

func read(fpath string, magic []byte) ([]Block, error) {
	data, err := unxor(fpath)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	blocks := make([]Block, 0)
	p := &parser{}
	for p.offset < len(data) {
		boffset := p.offset
		b, err := p.readBlock(data, magic)
		if err != nil {
			if isEndOfFile(fpath, boffset) {
				break
			}
			return nil, errors.Wrap(err, fmt.Sprintf("block offset %d", boffset))
		}

		blocks = append(blocks, b)
	}
	return blocks, nil
}

func (p *parser) readBlock(data, magic []byte) (Block, error) {
	var b Block
	p.checkMagic(data, magic)
	b.Size = p.readInt32(data)

	// Block header.
	headerOffset := p.offset
	b.Header.Version = p.readBytes(data, 4)
	b.Header.PrevBlock = p.readBytes(data, 32)
	b.Header.MerkleRoot = p.readBytesRev(data, 32)
	b.Header.Time = p.readTime(data)
	b.Header.Target = p.readBytesRev(data, 4)
	b.Header.Nonce = p.readBytesRev(data, 4)
	b.Hash = getID(data[headerOffset:p.offset])
	if p.err != nil {
		return Block{}, errors.Wrap(p.err, "parse header fail")
	}

	// Transactions.
	txLen := p.varInt(data)
	for i := range txLen {
		tx := p.readTransaction(data)
		if p.err != nil {
			return Block{}, errors.Wrap(p.err, fmt.Sprintf("transaction number %d", i))
		}
		b.Transaction = append(b.Transaction, tx)
	}

	// Check merkle root.
	merkleRoot, mutated := computeTxMerkleRoot(b.Transaction)
	if !bytes.Equal(merkleRoot, b.Header.MerkleRoot) {
		return Block{}, errors.Errorf("merkle root got %x want %x at block %x", merkleRoot, b.Header.MerkleRoot, b.Hash)
	}
	if mutated {
		return Block{}, errors.Errorf("merkle tree mutated at block %x", b.Hash)
	}

	return b, nil
}

func (p *parser) readTransaction(data []byte) Transaction {
	var tx Transaction
	tx.Version = p.readInt32(data)
	tx.Marker = p.readByte(data)
	var segwit bool
	if tx.Marker == 0 {
		segwit = true
		tx.Flag = p.readByte(data)
	} else {
		p.offset--
	}

	// Inputs and outputs.
	inputLen := p.varInt(data)
	for range inputLen {
		var inp Input
		inp.PrevOut.TxID = p.readBytes(data, 32)
		inp.PrevOut.Vout = p.readInt32(data)
		scriptLen := p.varInt(data)
		inp.Script = p.readBytes(data, scriptLen)
		inp.Sequence = p.readBytes(data, 4)
		tx.Input = append(tx.Input, inp)
	}
	outputLen := p.varInt(data)
	for range outputLen {
		var out Output
		out.Amount = p.readInt64(data)
		scriptLen := p.varInt(data)
		out.Script = p.readBytes(data, scriptLen)
		tx.Output = append(tx.Output, out)
	}

	// Witness.
	if segwit {
		for i := range inputLen {
			itemLen := p.varInt(data)
			for range itemLen {
				l := p.varInt(data)
				item := p.readBytes(data, l)
				tx.Input[i].Witness = append(tx.Input[i].Witness, item)
			}
		}
	}

	tx.LockTime = p.readInt32(data)
	return tx
}

func computeTxMerkleRoot(txs []Transaction) ([]byte, bool) {
	hashes := make([][]byte, 0, len(txs))
	for _, tx := range txs {
		buf := make([]byte, len(tx.ID()))
		copy(buf, tx.ID())
		slices.Reverse(buf)
		hashes = append(hashes, buf)
	}
	mr, mutation := computeMerkleRoot(hashes)
	slices.Reverse(mr)
	return mr, mutation
}

func computeMerkleRoot(hashes [][]byte) ([]byte, bool) {
	var mutation bool
	for len(hashes) > 1 {
		for pos := 0; pos+1 < len(hashes); pos += 2 {
			if bytes.Equal(hashes[pos], hashes[pos+1]) {
				mutation = true
			}
		}
		if len(hashes)%2 == 1 {
			last := hashes[len(hashes)-1]
			hashes = append(hashes, last)
		}

		out := 0
		for in := 0; in+1 < len(hashes); in += 2 {
			pair := append(hashes[in], hashes[in+1]...)
			hashes[out] = crypto.DoubleSha256(pair)
			out++
		}
		hashes = hashes[:out]
	}
	return hashes[0], mutation
}

type parser struct {
	offset int
	err    error
}

func (p *parser) varInt(data []byte) int {
	if p.err != nil {
		return -1
	}
	i, n := bitcoin.DecodeVarInt(data[p.offset:])
	p.offset += n
	return i
}

func (p *parser) readTime(data []byte) time.Time {
	if p.err != nil {
		return time.Time{}
	}
	unixtime := binary.LittleEndian.Uint32(data[p.offset:])
	tm := time.Unix(int64(unixtime), 0)
	p.offset += 4
	return tm
}

func (p *parser) readBytesRev(data []byte, n int) []byte {
	bs := p.readBytes(data, n)
	buf := make([]byte, len(bs))
	copy(buf, bs)
	slices.Reverse(buf)
	return buf
}

func (p *parser) readBytes(data []byte, n int) []byte {
	if p.err != nil {
		return nil
	}
	if p.offset+n >= len(data) {
		p.err = errors.Errorf("%d + %d >= %d", p.offset, n, len(data))
		return nil
	}
	bs := data[p.offset : p.offset+n]
	p.offset += n
	return bs
}

func (p *parser) readByte(data []byte) byte {
	if p.err != nil {
		return 255
	}
	b := data[p.offset]
	p.offset++
	return b
}

func (p *parser) readInt64(data []byte) uint64 {
	if p.err != nil {
		return math.MaxUint64
	}
	i := binary.LittleEndian.Uint64(data[p.offset:])
	p.offset += 8
	return i
}

func (p *parser) readInt32(data []byte) uint32 {
	if p.err != nil {
		return math.MaxUint32
	}
	d := data[p.offset : p.offset+4]
	i := binary.LittleEndian.Uint32(d)
	p.offset += 4
	return i
}

func (p *parser) checkMagic(data []byte, magic []byte) {
	if p.err != nil {
		return
	}
	if !bytes.Equal(data[p.offset:p.offset+4], magic) {
		p.err = errors.Errorf("wrong magic got %x want %x", data[p.offset:p.offset+4], magic)
		return
	}
	p.offset += 4
}

func unxor(fpath string) ([]byte, error) {
	dir := filepath.Dir(fpath)
	xorkey, err := os.ReadFile(filepath.Join(dir, "xor.dat"))
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	xored, err := os.ReadFile(fpath)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	unxored := make([]byte, 0, len(xored))
	for i, b := range xored {
		xori := i % len(xorkey)
		unxored = append(unxored, b^xorkey[xori])
	}
	return unxored, nil
}

func getID(data []byte) []byte {
	b := crypto.DoubleSha256(data)
	slices.Reverse(b)
	return b
}

func isEndOfFile(fpath string, offset int) bool {
	f, err := os.Open(fpath)
	if err != nil {
		return false
	}
	defer f.Close()

	f.Seek(int64(offset), io.SeekStart)
	b := make([]byte, 4096)
	for {
		n, err := f.Read(b)
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}

		for i := range n {
			if b[i] != 0 {
				return false
			}
		}
	}

	return true
}

// signetMagic returns the [magic bytes] for a signet. Unlike the mainnet whose magic bytes are fixed, signets' magic bytes are [calculated] from its challenge.
//
// [magic bytes]: https://learnmeabitcoin.com/technical/networking/magic-bytes/
// [calculated]: https://github.com/bitcoin/bitcoin/blob/082bb1a1047e9699605060aa93f17bb55110e062/src/kernel/chainparams.cpp#L517
func signetMagic(challengeHex string) ([]byte, error) {
	challenge, err := hex.DecodeString(challengeHex)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	serialized := append([]byte{byte(len(challenge))}, challenge...)
	hashed := sha256.Sum256(serialized)
	hashed = sha256.Sum256(hashed[:])
	return hashed[:4], nil
}
