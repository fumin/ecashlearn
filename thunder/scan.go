package thunder

import (
	"bytes"
	"slices"

	"github.com/fumin/ecashlearn/util"
	"github.com/pkg/errors"
)

type Block struct {
	Hash   []byte
	Header Header
	Body   Body
}

func scan(dbPath string) ([]Block, error) {
	headers, err := util.ScanDB(dbPath, dbHeaders)
	if err != nil {
		return nil, errors.Wrap(err, "")
	}
	blocksUnsorted := make([]Block, 0)
	for _, h := range headers {
		blockHash := h.K
		header, err := getBlockHeader(dbPath, blockHash)
		if err != nil {
			return nil, errors.Wrap(err, "")
		}
		body, err := getBlockBody(dbPath, blockHash)
		if err != nil {
			return nil, errors.Wrap(err, "")
		}
		blocksUnsorted = append(blocksUnsorted, Block{Hash: blockHash, Header: header, Body: body})
	}

	// Find genesis block.
	genesisI := -1
	for i, b := range blocksUnsorted {
		if b.Header.PrevSideHash == nil {
			if genesisI >= 0 {
				return nil, errors.Errorf("duplicate genesis %d", genesisI)
			}
			genesisI = i
		}
	}
	blocks := make([]Block, 0, len(blocksUnsorted))
	blocks = append(blocks, blocksUnsorted[genesisI])
	blocksUnsorted = slices.Delete(blocksUnsorted, genesisI, genesisI+1)

	// Grow the blockchain.
	for len(blocksUnsorted) > 0 {
		prev := blocks[len(blocks)-1]
		nextI := -1
		for i, b := range blocksUnsorted {
			psh := b.Header.PrevSideHash
			if bytes.Equal((*psh)[:], prev.Hash) {
				nextI = i
				break
			}
		}

		blocks = append(blocks, blocksUnsorted[nextI])
		blocksUnsorted = slices.Delete(blocksUnsorted, nextI, nextI+1)
	}

	return blocks, nil
}
