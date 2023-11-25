// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// AlexfAccountAbstractionTx represents an RIP-7560 transaction.
type AlexfAccountAbstractionTx struct {
	ChainID    *big.Int
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	// extra fields
	Sender        *common.Address
	Signature     []byte
	PaymasterData []byte
	DeployerData  []byte
	BuilderFee    *big.Int
	ValidationGas uint64
	PaymasterGas  uint64
	BigNonce      *big.Int // AA nonce is 256 bits wide

	// removed fields
	//Nonce      uint64
	// Signature values
	// V *big.Int `json:"v" gencodec:"required"`
	// R *big.Int `json:"r" gencodec:"required"`
	// S *big.Int `json:"s" gencodec:"required"`
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *AlexfAccountAbstractionTx) copy() TxData {
	cpy := &AlexfAccountAbstractionTx{
		BigNonce: tx.BigNonce,
		To:       copyAddressPtr(tx.To),
		Data:     common.CopyBytes(tx.Data),
		Gas:      tx.Gas,
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasTipCap:  new(big.Int),
		GasFeeCap:  new(big.Int),
		//V:          new(big.Int),
		//R:          new(big.Int),
		//S:          new(big.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	//if tx.V != nil {
	//	cpy.V.Set(tx.V)
	//}
	//if tx.R != nil {
	//	cpy.R.Set(tx.R)
	//}
	//if tx.S != nil {
	//	cpy.S.Set(tx.S)
	//}
	return cpy
}

// accessors for innerTx.
func (tx *AlexfAccountAbstractionTx) txType() byte           { return ALEXF_AA_TX_TYPE }
func (tx *AlexfAccountAbstractionTx) chainID() *big.Int      { return tx.ChainID }
func (tx *AlexfAccountAbstractionTx) accessList() AccessList { return tx.AccessList }
func (tx *AlexfAccountAbstractionTx) data() []byte           { return tx.Data }
func (tx *AlexfAccountAbstractionTx) gas() uint64            { return tx.Gas }
func (tx *AlexfAccountAbstractionTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *AlexfAccountAbstractionTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *AlexfAccountAbstractionTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *AlexfAccountAbstractionTx) value() *big.Int        { return tx.Value }
func (tx *AlexfAccountAbstractionTx) nonce() uint64          { return 0 }
func (tx *AlexfAccountAbstractionTx) bigNonce() *big.Int     { return tx.BigNonce }
func (tx *AlexfAccountAbstractionTx) to() *common.Address    { return tx.To }

func (tx *AlexfAccountAbstractionTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

func (tx *AlexfAccountAbstractionTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

func (tx *AlexfAccountAbstractionTx) setSignatureValues(chainID, v, r, s *big.Int) {
	//tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}

func (tx *AlexfAccountAbstractionTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *AlexfAccountAbstractionTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}
