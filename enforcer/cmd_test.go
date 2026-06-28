package enforcer

import (
	"encoding/hex"
	"testing"

	"github.com/fumin/ecashlearn/blkdat"
	"github.com/fumin/ecashlearn/util"
)

func TestListDBs(t *testing.T) {
	t.Logf("Enforcer")
	dbs, err := util.ListDBs("../testdata/enforcer/signet.mdb")
	if err != nil {
		t.Errorf("%+v", err)
	}
	want := 18
	if len(dbs) != want {
		t.Errorf("%d != %d", len(dbs), want)
	}
	for _, name := range dbs {
		t.Logf("\t%s", name)
	}

	t.Logf("Thunder chain")
	dbs, err = util.ListDBs("../testdata/thunder/data.mdb")
	if err != nil {
		t.Errorf("%+v", err)
	}
	for _, name := range dbs {
		t.Logf("\t%s", name)
	}

	t.Logf("Thunder wallet")
	dbs, err = util.ListDBs("../testdata/thunder/wallet.mdb")
	if err != nil {
		t.Errorf("%+v", err)
	}
	for _, name := range dbs {
		t.Logf("\t%s", name)
	}
}

func TestScanDB(t *testing.T) {
	// dbPath := "/home/shaoyu/.local/share/bip300301_enforcer/validator/signet/signet.mdb"
	dbPath := "../testdata/enforcer/signet.mdb"
	// dbPath := "../testdata/thunder/data.mdb"
	// dbPath := "../testdata/thunder/wallet.mdb"
	dbName := "active_sidechain_number_to_pending_m6ids"
	contents, err := util.ScanDB(dbPath, dbName)
	if err != nil {
		t.Errorf("%+v", err)
	}
	for i, kv := range contents {
		t.Logf("%d %x\"%s\" %x\"%s\"", i, kv.K, kv.K, kv.V, kv.V)
	}
}

func TestScanMsgs(t *testing.T) {
	const (
		challenge  = "00148835832e28c816b7acd8fdb19772ab2199603a56"
		fpath      = "../testdata/bitcoind/blk00000.dat"
		enforcerDB = "../testdata/enforcer/signet.mdb"
		// fpath      = "/home/shaoyu/.drivechain/signet/blocks/blk00000.dat"
		// enforcerDB = "/home/shaoyu/.local/share/bip300301_enforcer/validator/signet/signet.mdb"
	)
	blocks, err := blkdat.Read(fpath, challenge)
	if err != nil {
		t.Errorf("%+v", err)
	}
	txMap := make(map[string]blkdat.Transaction)
	for _, b := range blocks {
		for _, tx := range b.Transaction {
			txMap[hex.EncodeToString(tx.ID())] = tx
		}
	}
	d2 := newD2()

	for height, b := range blocks {
		ms, err := getMessages(b, txMap)
		if err != nil {
			t.Errorf("%+v", err)
		}
		for i := range ms {
			ms[i].Height = height
		}
		if err := d2.HandleMsgs(ms, height); err != nil {
			t.Errorf("%+v", err)
		}

		// Print the messages.
		for _, m := range ms {
			if _, ok := m.Msg.(M7); ok {
				continue
			}
			t.Logf("%s", FormatMessage(d2, m))
		}
	}
}
