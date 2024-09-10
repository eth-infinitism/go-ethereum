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

func abiEncodePostPaymasterTransaction(success bool, actualGasCost uint64, context []byte) []byte {
	// TODO: pass actual gas cost parameter here!
	postOpData, err := Rip7560Abi.Pack("postPaymasterTransaction", success, big.NewInt(int64(actualGasCost)), context)
	if err != nil {
		panic("unable to encode postPaymasterTransaction")
	}
	return postOpData
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

func abiDecodeAcceptAccount(input []byte, allowSigFail bool) (*AcceptAccountData, error) {
	acceptAccountData := &AcceptAccountData{}
	err := decodeMethodParamsToInterface(acceptAccountData, "acceptAccount", input)
	if err != nil && allowSigFail {
		err = decodeMethodParamsToInterface(acceptAccountData, "sigFailAccount", input)
	}
	if err != nil {
		return nil, err
	}
	return acceptAccountData, nil
}

func abiDecodeAcceptPaymaster(input []byte, allowSigFail bool) (*AcceptPaymasterData, error) {
	acceptPaymasterData := &AcceptPaymasterData{}
	err := decodeMethodParamsToInterface(acceptPaymasterData, "acceptPaymaster", input)
	if err != nil && allowSigFail {
		err = decodeMethodParamsToInterface(acceptPaymasterData, "sigFailPaymaster", input)
	}
	if err != nil {
		return nil, err
	}
	if len(acceptPaymasterData.Context) > PaymasterMaxContextSize {
		return nil, errors.New("paymaster return data: context too large")
	}
	return acceptPaymasterData, err
}

func abiEncodeRIP7560TransactionEvent(
	aatx *types.Rip7560AccountAbstractionTx,
	executionStatus uint64,
) (topics []common.Hash, data []byte, error error) {
	id := Rip7560Abi.Events["RIP7560TransactionEvent"].ID
	paymaster := aatx.Paymaster
	if paymaster == nil {
		paymaster = &common.Address{}
	}
	deployer := aatx.Deployer
	if deployer == nil {
		deployer = &common.Address{}
	}
	inputsAll := Rip7560Abi.Events["RIP7560TransactionEvent"].Inputs
	inputs := inputsAll[3:] // todo: hack - hard-coding the "skipping" of indexed parameters
	data, error = inputs.Pack(
		// TODO: append NonceKey
		big.NewInt(int64(aatx.Nonce)),
		big.NewInt(int64(executionStatus)),
	)
	if error != nil {
		return nil, nil, error
	}
	topics = []common.Hash{id, {}, {}, {}}
	topics[1] = [32]byte(common.LeftPadBytes(aatx.Sender.Bytes()[:], 32))
	topics[2] = [32]byte(common.LeftPadBytes(paymaster.Bytes()[:], 32))
	topics[3] = [32]byte(common.LeftPadBytes(deployer.Bytes()[:], 32))
	return topics, data, nil
}

func abiEncodeRIP7560TransactionRevertReasonEvent(
	aatx *types.Rip7560AccountAbstractionTx,
	revertData []byte,
) (topics []common.Hash, data []byte, error error) {
	id := Rip7560Abi.Events["RIP7560TransactionRevertReason"].ID
	inputsAll := Rip7560Abi.Events["RIP7560TransactionRevertReason"].Inputs
	inputs := inputsAll[1:] // todo: hack - hard-coding the "skipping" of indexed parameters
	data, error = inputs.Pack(
		// TODO: append NonceKey
		big.NewInt(int64(aatx.Nonce)),
		revertData,
	)
	if error != nil {
		return nil, nil, error
	}
	topics = []common.Hash{id, {}}
	topics[1] = [32]byte(common.LeftPadBytes(aatx.Sender.Bytes()[:], 32))
	return topics, data, nil
}

func abiEncodeRIP7560TransactionPostOpRevertReasonEvent(
	aatx *types.Rip7560AccountAbstractionTx,
	revertData []byte,
) (topics []common.Hash, data []byte, error error) {
	id := Rip7560Abi.Events["RIP7560TransactionPostOpRevertReason"].ID
	paymaster := aatx.Paymaster
	if paymaster == nil {
		paymaster = &common.Address{}
	}
	inputsAll := Rip7560Abi.Events["RIP7560TransactionPostOpRevertReason"].Inputs
	inputs := inputsAll[2:] // todo: hack - hard-coding the "skipping" of indexed parameters
	data, error = inputs.Pack(
		// TODO: append NonceKey
		big.NewInt(int64(aatx.Nonce)),
		revertData,
	)
	if error != nil {
		return nil, nil, error
	}
	topics = []common.Hash{id, {}, {}}
	topics[1] = [32]byte(common.LeftPadBytes(aatx.Sender.Bytes()[:], 32))
	topics[2] = [32]byte(common.LeftPadBytes(paymaster.Bytes()[:], 32))
	return topics, data, nil
}
