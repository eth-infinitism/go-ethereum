package core

import (
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
)

// TODO: accept address as configuration parameter
var AA_NONCE_MANAGER = common.HexToAddress("0x59c405Dc6D032d9Ff675350FefC66F3b6c1bEbaB")

func prepareNonceManagerMessage(tx *types.Rip7560AccountAbstractionTx) []byte {

	return slices.Concat(
		tx.Sender.Bytes(),
		math.PaddedBigBytes(tx.NonceKey, 32),
		math.PaddedBigBytes(big.NewInt(int64(tx.Nonce)), 32),
	)
}
