package util

import (
	"github.com/PowerDNS/lmdb-go/lmdb"
	"github.com/pkg/errors"
)

func Get(dbPath, dbName string, key []byte) ([]byte, error) {
	env, err := lmdb.NewEnv()
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	defer env.Close()
	if err := env.SetMaxDBs(1); err != nil {
		return nil, errors.Wrap(err, "")
	}
	if err := env.Open(dbPath, 0, 0644); err != nil {
		return nil, errors.Wrap(err, "")
	}
	if _, err := env.ReaderCheck(); err != nil {
		return nil, errors.Wrap(err, "")
	}
	dbi, err := OpenDBI(env, dbName)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	var vShared []byte
	err = env.View(func(txn *lmdb.Txn) error {
		var err error
		vShared, err = txn.Get(dbi, key)
		if lmdb.IsNotFound(err) {
			return err
		}
		if err != nil {
			return errors.Wrap(err, "")
		}
		return nil
	})
	if lmdb.IsNotFound(err) {
		return nil, err
	}
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	v := make([]byte, len(vShared))
	copy(v, vShared)

	return v, nil
}

type KeyValue struct {
	K []byte
	V []byte
}

func ScanDB(dbPath, dbName string) ([]KeyValue, error) {
	env, err := lmdb.NewEnv()
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	defer env.Close()
	if err := env.SetMaxDBs(1); err != nil {
		return nil, errors.Wrap(err, "")
	}
	if err := env.Open(dbPath, 0, 0644); err != nil {
		return nil, errors.Wrap(err, "")
	}
	if _, err := env.ReaderCheck(); err != nil {
		return nil, errors.Wrap(err, "")
	}
	dbi, err := OpenDBI(env, dbName)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	contents := make([]KeyValue, 0)
	fn := func(k, v []byte) error {
		kb := make([]byte, len(k))
		copy(kb, k)
		vb := make([]byte, len(v))
		copy(vb, v)
		contents = append(contents, KeyValue{K: kb, V: vb})
		return nil
	}
	if err := scan(env, dbi, fn); err != nil {
		return nil, errors.Wrap(err, "")
	}
	return contents, nil
}

func ListDBs(dir string) ([]string, error) {
	env, err := lmdb.NewEnv()
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	defer env.Close()
	if err := env.Open(dir, 0, 0644); err != nil {
		return nil, errors.Wrap(err, "")
	}
	if _, err := env.ReaderCheck(); err != nil {
		return nil, errors.Wrap(err, "")
	}
	var root lmdb.DBI
	err = env.View(func(txn *lmdb.Txn) error {
		root, err = txn.OpenRoot(0)
		if err != nil {
			return errors.Wrap(err, "")
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "")
	}

	dbs := make([]string, 0)
	fn := func(k, v []byte) error {
		dbs = append(dbs, string(k))
		return nil
	}
	if err := scan(env, root, fn); err != nil {
		return nil, errors.Wrap(err, "")
	}

	return dbs, nil
}

func OpenDBI(env *lmdb.Env, name string) (lmdb.DBI, error) {
	var dbi lmdb.DBI
	err := env.View(func(txn *lmdb.Txn) error {
		var err error
		dbi, err = txn.OpenDBI(name, 0)
		if err != nil {
			return errors.Wrap(err, "")
		}
		return nil
	})
	if err != nil {
		return dbi, errors.Wrap(err, "")
	}
	return dbi, nil
}

func scan(env *lmdb.Env, dbi lmdb.DBI, fn func(k, v []byte) error) error {
	err := env.View(func(txn *lmdb.Txn) error {
		cur, err := txn.OpenCursor(dbi)
		if err != nil {
			return errors.Wrap(err, "")
		}
		defer cur.Close()
		for {
			k, v, err := cur.Get(nil, nil, lmdb.Next)
			if lmdb.IsNotFound(err) {
				break
			}
			if err != nil {
				return errors.Wrap(err, "")
			}
			if err := fn(k, v); err != nil {
				return errors.Wrap(err, "")
			}
		}
		return nil
	})
	if err != nil {
		return errors.Wrap(err, "")
	}
	return nil
}
