package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"
	"time"

	"github.com/LayerTwo-Labs/sidesail/sidechain-orchestrator/sidechain/thunder"
	"github.com/pkg/errors"
)

func mainWithErr() error {
	client := thunder.NewClient("127.0.0.1", 6009)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	balance, err := client.Balance(ctx)
	if err != nil {
		return errors.Wrap(err, "")
	}
	log.Printf("%#v", balance)

	// bundle, err := client.PendingWithdrawalBundle(ctx)
	// if err != nil {
	// 	return errors.Wrap(err, "")
	// }
	// log.Printf("%#v", string(bundle))

	// txhex := "7a5d84fa6f91fadda1eb8b012a2db9ed7910dfe26b662033a26009a6bada6901"
	// if err := removeFromMempool(ctx, client, txhex); err != nil {
	// 	return errors.Wrap(err, "")
	// }
	return nil
}

func removeFromMempool(ctx context.Context, client *thunder.Client, txhex string) error {
	txid, err := hex.DecodeString(txhex)
	if err != nil {
		return errors.Wrap(err, "")
	}
	if err := client.RemoveFromMempool(ctx, string(txid)); err != nil {
		return errors.Wrap(err, "")
	}
	return nil
}

func main() {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds | log.Llongfile | log.LstdFlags)

	if err := mainWithErr(); err != nil {
		log.Fatalf("%+v", err)
	}
}
