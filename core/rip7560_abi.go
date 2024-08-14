package core

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"strings"
)

var Rip7560Abi, err = abi.JSON(strings.NewReader(Rip7560AbiJson))

type AcceptAccountData struct {
	ValidAfter *big.Int
	ValidUntil *big.Int
}

type AcceptPaymasterData struct {
	ValidAfter *big.Int
	ValidUntil *big.Int
	Context    []byte
}

func abiEncodeValidateTransaction(tx *types.Rip7560AccountAbstractionTx, signingHash common.Hash) ([]byte, error) {

	txAbiEncoding, err := tx.AbiEncode()
	if err != nil {
		return nil, err
	}
	validateTransactionData, err := Rip7560Abi.Pack("validateTransaction", big.NewInt(Rip7560AbiVersion), signingHash, txAbiEncoding)
	return validateTransactionData, err
}

func abiEncodeValidatePaymasterTransaction(tx *types.Rip7560AccountAbstractionTx, signingHash common.Hash) ([]byte, error) {
	txAbiEncoding, err := tx.AbiEncode()
	if err != nil {
		return nil, err
	}
	data, err := Rip7560Abi.Pack("validatePaymasterTransaction", big.NewInt(Rip7560AbiVersion), signingHash, txAbiEncoding)
	return data, err
}

func abiEncodePostPaymasterTransaction(context []byte) ([]byte, error) {
	// TODO: pass actual gas cost parameter here!
	postOpData, err := Rip7560Abi.Pack("postPaymasterTransaction", true, big.NewInt(0), context)
	return postOpData, err
}

func decodeMethodParamsToInterface(output interface{}, methodName string, input []byte) error {
	m, err := Rip7560Abi.MethodById(input)
	if err != nil {
		return fmt.Errorf("unable to decode %s: %w", methodName, err)
	}
	if methodName != m.Name {
		return fmt.Errorf("unable to decode %s: got wrong method %s", methodName, m.Name)
	}
	params, err := m.Inputs.Unpack(input[4:])
	if err != nil {
		return fmt.Errorf("unable to decode %s: %w", methodName, err)
	}
	err = m.Inputs.Copy(output, params)
	if err != nil {
		return fmt.Errorf("unable to decode %s: %v", methodName, err)
	}
	return nil
}

func abiDecodeAcceptAccount(input []byte) (*AcceptAccountData, error) {
	acceptAccountData := &AcceptAccountData{}
	err := decodeMethodParamsToInterface(acceptAccountData, "acceptAccount", input)
	if err != nil {
		return nil, err
	}
	return acceptAccountData, nil
}

func abiDecodeAcceptPaymaster(input []byte) (*AcceptPaymasterData, error) {
	acceptPaymasterData := &AcceptPaymasterData{}
	err := decodeMethodParamsToInterface(acceptPaymasterData, "acceptPaymaster", input)
	if err != nil {
		return nil, err
	}
	if len(acceptPaymasterData.Context) > PaymasterMaxContextSize {
		return nil, errors.New("paymaster return data: context too large")
	}
	return acceptPaymasterData, err
}
