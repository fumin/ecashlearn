package util

import (
	"os"
	"testing"

	"github.com/PowerDNS/lmdb-go/lmdb"
	"github.com/pkg/errors"
)

func TestCopy(t *testing.T) {
	return
	src := "../data/thunder/ori_data.mdb"
	dst := "../data/thunder/data.mdb"

	env, err := lmdb.NewEnv()
	if err != nil {
		t.Errorf("%+v", err)
	}
	defer env.Close()
	if err := env.Open(src, 0, 0644); err != nil {
		t.Errorf("%+v", err)
	}
	if _, err := env.ReaderCheck(); err != nil {
		t.Errorf("%+v", err)
	}

	// mdb_env_copy requires the destination folder to be exist.
	if err := os.MkdirAll(dst, 0755); err != nil {
		t.Errorf("%+v", err)
	}
	const MDB_CP_COMPACT = 0x01
	if err := env.CopyFlag(dst, MDB_CP_COMPACT); err != nil {
		t.Errorf("%+v", err)
	}
}

func TestDBSize(t *testing.T) {
	dbPath := "../testdata/thunder/data.mdb"
	// dbPath = "/home/shaoyu/.local/share/thunder/data.mdb"
	dbs, err := ListDBs(dbPath)
	if err != nil {
		t.Errorf("%+v", err)
	}
	var totalSize int
	for _, dbName := range dbs {
		size, err := getSize(dbPath, dbName)
		if err != nil {
			t.Errorf("%s %+v", dbName, err)
		}
		totalSize += size
		t.Logf("%s %d", dbName, size)
	}
	t.Logf("total %d", totalSize)
}

func getSize(dbPath, dbName string) (int, error) {
	env, err := lmdb.NewEnv()
	if err != nil {
		return -1, errors.Wrap(err, "")
	}
	defer env.Close()
	if err := env.SetMaxDBs(1); err != nil {
		return -1, errors.Wrap(err, "")
	}
	if err := env.Open(dbPath, 0, 0644); err != nil {
		return -1, errors.Wrap(err, "")
	}
	if _, err := env.ReaderCheck(); err != nil {
		return -1, errors.Wrap(err, "")
	}
	dbi, err := OpenDBI(env, dbName)
	if err != nil {
		return -1, errors.Wrap(err, "")
	}

	var size int
	fn := func(k, v []byte) error {
		size += len(k)
		size += len(v)
		return nil
	}
	if err := scan(env, dbi, fn); err != nil {
		return -1, errors.Wrap(err, "")
	}
	return size, nil
}
