package core

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"slices"
)

// TODO: accept address as configuration parameter
var AA_NONCE_MANAGER = common.HexToAddress("0x2A9D5743c62dC9420ca7B40E443C966a9527E762")

func prepareNonceManagerMessage(tx *types.Rip7560AccountAbstractionTx) []byte {

	return slices.Concat(
		tx.Sender.Bytes(),
		math.PaddedBigBytes(tx.NonceKey, 32),
		math.PaddedBigBytes(big.NewInt(int64(tx.Nonce)), 32),
	)
}
