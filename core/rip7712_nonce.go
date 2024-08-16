package core

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
	"math/big"
)

// TODO: accept address as configuration parameter
var AA_NONCE_MANAGER = common.HexToAddress("0x63f63e798f5F6A934Acf0a3FD1C01f3Fac851fF0")

func prepareNonceManagerMessage(baseTx *types.Transaction) *Message {
	tx := baseTx.Rip7560TransactionData()
	key := make([]byte, 32)
	fromBig, _ := uint256.FromBig(tx.BigNonce)
	fromBig.WriteToSlice(key)

	nonceManagerData := make([]byte, 0)
	nonceManagerData = append(nonceManagerData[:], tx.Sender.Bytes()...)
	nonceManagerData = append(nonceManagerData[:], key...)
	return &Message{
		From:              AA_ENTRY_POINT,
		To:                &AA_NONCE_MANAGER,
		Value:             big.NewInt(0),
		GasLimit:          100000,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              nonceManagerData,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsRip7560Frame:    true,
	}
}
