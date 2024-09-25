package core

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"slices"
)

// TODO: accept address as configuration parameter
var AA_NONCE_MANAGER = common.HexToAddress("0x63f63e798f5F6A934Acf0a3FD1C01f3Fac851fF0")

func prepareNonceManagerMessage(tx *types.Rip7560AccountAbstractionTx) []byte {

	return slices.Concat(
		tx.Sender.Bytes(),
		math.PaddedBigBytes(tx.NonceKey, 24),
		math.PaddedBigBytes(big.NewInt(int64(tx.Nonce)), 8),
	)
}
