package enforcer

import (
	"encoding/binary"
	"math"

	"github.com/PowerDNS/lmdb-go/lmdb"
	"github.com/fumin/ecashlearn/bitcoin"
	"github.com/fumin/ecashlearn/util"
	"github.com/fumin/ecashlearn/util/bincode"
	"github.com/pkg/errors"
)

type database struct {
	env                    *lmdb.Env
	ctip                   lmdb.DBI
	ctipOutpointToValueSeq lmdb.DBI
	treasuryUtxoCount      lmdb.DBI
}

func newDatabase(dbPath string) (*database, error) {
	db := &database{}
	var err error
	db.env, err = lmdb.NewEnv()
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	if err := db.env.SetMaxDBs(18); err != nil {
		return nil, errors.Wrap(err, "")
	}
	if err := db.env.Open(dbPath, 0, 0644); err != nil {
		return nil, errors.Wrap(err, "")
	}
	if _, err := db.env.ReaderCheck(); err != nil {
		return nil, errors.Wrap(err, "")
	}

	// Ctip maps slot to ctip.
	db.ctip, err = util.OpenDBI(db.env, "active_sidechain_number_to_ctip")
	// CtipOutpointToValueSeq maps outpoint to slot.
	// It is the reverse of db.ctip.
	db.ctipOutpointToValueSeq, err = util.OpenDBI(db.env, "active_sidechain_ctip_outpoint_to_value_seq")

	db.treasuryUtxoCount, err = util.OpenDBI(db.env, "active_sidechain_number_to_treasury_utxo_count")
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	return db, nil
}

func (db *database) getCtip(txn *lmdb.Txn, sidechainN SidechainNumber) (Ctip, error) {
	b, err := txn.Get(db.ctip, []byte{sidechainN})
	if lmdb.IsNotFound(err) {
		return Ctip{}, err
	}
	if err != nil {
		return Ctip{}, errors.Wrap(err, "")
	}
	var v Ctip
	if err := bincode.Deserialize(&v, b); err != nil {
		return Ctip{}, errors.Wrap(err, "")
	}
	return v, nil
}

type getCtipOutpointToValueSeqValue struct {
	SidechainN SidechainNumber
	Amount     bitcoin.Amount
	Sequence   uint64
}

func (db *database) getCtipOutpointToValueSeq(txn *lmdb.Txn, out bitcoin.Outpoint) (getCtipOutpointToValueSeqValue, error) {
	outB, err := bincode.Serialize(out)
	if err != nil {
		return getCtipOutpointToValueSeqValue{}, errors.Wrap(err, "")
	}
	b, err := txn.Get(db.ctipOutpointToValueSeq, outB)
	if lmdb.IsNotFound(err) {
		return getCtipOutpointToValueSeqValue{}, err
	}
	if err != nil {
		return getCtipOutpointToValueSeqValue{}, errors.Wrap(err, "")
	}
	var v getCtipOutpointToValueSeqValue
	if err := bincode.Deserialize(&v, b); err != nil {
		return getCtipOutpointToValueSeqValue{}, errors.Wrap(err, "")
	}
	return v, nil
}

func (db *database) getTreasuryUtxoCount(txn *lmdb.Txn, sidechainN SidechainNumber) (uint64, error) {
	b, err := txn.Get(db.treasuryUtxoCount, []byte{sidechainN})
	if lmdb.IsNotFound(err) {
		return math.MaxUint64, err
	}
	if err != nil {
		return math.MaxUint64, errors.Wrap(err, "")
	}
	cnt := binary.LittleEndian.Uint64(b)
	return cnt, nil
}
