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
	// TODO: this can probably be done a lot easier, check syntax
	tx := baseTx.Rip7560TransactionData()
	nonceKey := make([]byte, 24)
	nonce := make([]byte, 8)
	nonceKey256, _ := uint256.FromBig(tx.NonceKey)
	nonce256 := uint256.NewInt(tx.Nonce)
	nonceKey256.WriteToSlice(nonceKey)
	nonce256.WriteToSlice(nonce)

	nonceManagerData := make([]byte, 0)
	nonceManagerData = append(nonceManagerData[:], tx.Sender.Bytes()...)
	nonceManagerData = append(nonceManagerData[:], nonceKey...)
	nonceManagerData = append(nonceManagerData[:], nonce...)
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
