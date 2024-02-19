package types

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

type Rip7560AccountAbstractionHeaderTx struct {
	ChainID *big.Int

	TransactionsCount uint64
}

func (r Rip7560AccountAbstractionHeaderTx) txType() byte {
	return Rip7560Type
}

func (r Rip7560AccountAbstractionHeaderTx) chainID() *big.Int {
	return r.ChainID
}

func (r Rip7560AccountAbstractionHeaderTx) copy() TxData {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) accessList() AccessList {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) data() []byte {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) gas() uint64 {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) gasPrice() *big.Int {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) gasTipCap() *big.Int {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) gasFeeCap() *big.Int {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) value() *big.Int {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) nonce() uint64 {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) to() *common.Address {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) rawSignatureValues() (v, r, s *big.Int) {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) setSignatureValues(chainID, v, r, s *big.Int) {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) encode(buffer *bytes.Buffer) error {
	//TODO implement me
	panic("implement me")
}

func (r Rip7560AccountAbstractionHeaderTx) decode(bytes []byte) error {
	//TODO implement me
	panic("implement me")
}
