package core

import (
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func Test_abiDecodeAcceptAccount(t *testing.T) {
	packed, err := Rip7560Abi.Pack("acceptAccount", big.NewInt(1), big.NewInt(2))
	if err != nil {
		assert.Failf(t, "failed to encode acceptAccount", "error: %v", err)
		return
	}
	acceptAccountData, err := abiDecodeAcceptAccount(packed)
	if err != nil {
		assert.Failf(t, "failed to decode acceptAccount", "error: %v", err)
		return
	}
	assert.Equal(t, AcceptAccountData{
		ValidAfter: big.NewInt(1),
		ValidUntil: big.NewInt(2),
	}, *acceptAccountData)
}

func Test_abiDecodeAcceptPaymaster(t *testing.T) {
	context := []byte{0x03, 0x04, 0x05}
	packed, err := Rip7560Abi.Pack("acceptPaymaster", big.NewInt(1), big.NewInt(2), context)
	assert.NoError(t, err)
	acceptPaymasterData, err := abiDecodeAcceptPaymaster(packed)
	assert.NoError(t, err)
	assert.Equal(t, AcceptPaymasterData{
		ValidAfter: big.NewInt(1),
		ValidUntil: big.NewInt(2),
		Context:    context,
	}, *acceptPaymasterData)
}

func Test_abiDecodeAcceptAccount_wrongSig(t *testing.T) {
	packed, err := Rip7560Abi.Pack("acceptAccount", big.NewInt(1), big.NewInt(2))
	assert.NoError(t, err)

	wrongSig := append([]byte{0x00}, packed[1:]...)
	_, err = abiDecodeAcceptAccount(wrongSig)

	assert.EqualError(t, err, "unable to decode acceptAccount: no method with id: 0x0056ebd1")

	wrongData := packed[:len(packed)-1]
	_, err = abiDecodeAcceptAccount(wrongData)
	assert.EqualError(t, err, "unable to decode acceptAccount: abi: cannot marshal in to go type: length insufficient 63 require 64")

	pmPacked, err := Rip7560Abi.Pack("acceptPaymaster", big.NewInt(1), big.NewInt(2), []byte{0x01})
	assert.NoError(t, err)

	wrongMethodSig := append(pmPacked[0:4], packed[4:]...)
	_, err = abiDecodeAcceptAccount(wrongMethodSig)

	assert.EqualError(t, err, "unable to decode acceptAccount: got wrong method acceptPaymaster")
}
