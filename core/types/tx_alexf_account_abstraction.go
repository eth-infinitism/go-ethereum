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
	"github.com/ethereum/go-ethereum/accounts/abi"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// AlexfAccountAbstractionTx represents an RIP-7560 transaction.
type AlexfAccountAbstractionTx struct {
	// overlapping fields
	ChainID    *big.Int
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas
	Gas        uint64
	To         *common.Address
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
	Nonce uint64
	Value *big.Int
	// Signature values
	// V *big.Int `json:"v" gencodec:"required"`
	// R *big.Int `json:"r" gencodec:"required"`
	// S *big.Int `json:"s" gencodec:"required"`
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *AlexfAccountAbstractionTx) copy() TxData {
	cpy := &AlexfAccountAbstractionTx{
		To:   copyAddressPtr(tx.To),
		Data: common.CopyBytes(tx.Data),
		Gas:  tx.Gas,
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasTipCap:  new(big.Int),
		GasFeeCap:  new(big.Int),

		BigNonce:      new(big.Int),
		Sender:        copyAddressPtr(tx.Sender),
		Signature:     common.CopyBytes(tx.Signature),
		PaymasterData: common.CopyBytes(tx.PaymasterData),
		DeployerData:  common.CopyBytes(tx.DeployerData),
		BuilderFee:    new(big.Int),
		ValidationGas: tx.ValidationGas,
		PaymasterGas:  tx.PaymasterGas,
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
	if tx.BigNonce != nil {
		cpy.BigNonce.Set(tx.BigNonce)
	}
	if tx.BuilderFee != nil {
		cpy.BuilderFee.Set(tx.BuilderFee)
	}
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

// TransactionType4 an equivalent of a solidity struct only used to encode the 'transaction' parameter
type TransactionType4 struct {
	Sender               common.Address
	Nonce                *big.Int
	ValidationGasLimit   *big.Int
	PaymasterGasLimit    *big.Int
	CallGasLimit         *big.Int
	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
	BuilderFee           *big.Int
	PaymasterData        []byte
	DeployerData         []byte
	CallData             []byte
	Signature            []byte
}

func (tx *AlexfAccountAbstractionTx) AbiEncode() ([]byte, error) {

	//struct TransactionType4 {
	//	address sender;
	//	uint256 nonce;
	//	uint256 validationGasLimit;
	//	uint256 paymasterGasLimit;
	//	uint256 callGasLimit;
	//	uint256 maxFeePerGas;
	//	uint256 maxPriorityFeePerGas;
	//	uint256 builderFee;
	//	bytes paymasterData;
	//	bytes deployerData;
	//	bytes callData;
	//	bytes signature;
	//}

	structThing, _ := abi.NewType("tuple", "struct thing", []abi.ArgumentMarshaling{
		{Name: "sender", Type: "address"},
		{Name: "nonce", Type: "uint256"},
		{Name: "validationGasLimit", Type: "uint256"},
		{Name: "paymasterGasLimit", Type: "uint256"},
		{Name: "callGasLimit", Type: "uint256"},
		{Name: "maxFeePerGas", Type: "uint256"},
		{Name: "maxPriorityFeePerGas", Type: "uint256"},
		{Name: "builderFee", Type: "uint256"},
		{Name: "paymasterData", Type: "bytes"},
		{Name: "deployerData", Type: "bytes"},
		{Name: "callData", Type: "bytes"},
		{Name: "signature", Type: "bytes"},
	})

	args := abi.Arguments{
		{Type: structThing, Name: "param_one"},
	}
	record := &TransactionType4{
		Sender:               *tx.Sender,
		Nonce:                tx.BigNonce,
		ValidationGasLimit:   big.NewInt(int64(tx.ValidationGas)), // todo: awkward uint64->int64 conversions here, why?
		PaymasterGasLimit:    big.NewInt(int64(tx.PaymasterGas)),
		CallGasLimit:         big.NewInt(int64(tx.Gas)),
		MaxFeePerGas:         tx.GasFeeCap,
		MaxPriorityFeePerGas: tx.GasTipCap,
		BuilderFee:           tx.BuilderFee,
		PaymasterData:        tx.PaymasterData,
		DeployerData:         tx.DeployerData,
		CallData:             tx.Data,
		Signature:            tx.Signature,
	}
	packed, err := args.Pack(&record)
	return packed, err
}