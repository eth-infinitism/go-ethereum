package rip7560

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"math/big"
	"testing"
)

var DEFAULT_PAYMASTER = common.HexToAddress("0xaaaaaaaaaabbbbbbbbbbccccccccccdddddddddd")

func TestPaymasterValidationFailure_nobalance(t *testing.T) {

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(vm.PUSH0, vm.DUP1, vm.REVERT), 1), types.Rip7560AccountAbstractionTx{
		ValidationGas: 1000000000,
		GasFeeCap:     big.NewInt(1000000000),
		Paymaster:     &DEFAULT_PAYMASTER,
	}, "insufficient funds for gas * price + value: address 0xaaAaaAAAAAbBbbbbBbBBCCCCcCCCcCdddDDDdddd have 1 want 1000000000000000000")
}

func TestPaymasterValidationFailure_oog(t *testing.T) {

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(vm.PUSH0, vm.DUP1, vm.REVERT), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: 1000000000,
		GasFeeCap:     big.NewInt(1000000000),
		Paymaster:     &DEFAULT_PAYMASTER,
	}, "out of gas")
}
func TestPaymasterValidationFailure_revert(t *testing.T) {

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(vm.PUSH0, vm.DUP1, vm.REVERT), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000000),
		GasFeeCap:     big.NewInt(1000000000),
		Paymaster:     &DEFAULT_PAYMASTER,
		PaymasterGas:  1000000000,
	}, "execution reverted")
}

func TestPaymasterValidationFailure_unparseable_return_value(t *testing.T) {

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createAccountCode(), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: 1000000000,
		PaymasterGas:  1000000000,
		GasFeeCap:     big.NewInt(1000000000),
		Paymaster:     &DEFAULT_PAYMASTER,
	}, "invalid paymaster return data")
}

func TestPaymasterValidationFailure_wrong_magic(t *testing.T) {
	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), returnWithData(paymasterReturnValue(1, 2, 3, []byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: 1000000000,
		PaymasterGas:  1000000000,
		GasFeeCap:     big.NewInt(1000000000),
		Paymaster:     &DEFAULT_PAYMASTER,
	}, "paymaster did not return correct MAGIC_VALUE")
}

func TestPaymasterValidationFailure_contextTooLarge(t *testing.T) {
	//paymaster returning huge context.
	// first word is magic return value
	// 2nd word is offset (fixed 64)
	// 3rd word is length of context (max+1)
	// then we return the total length of above (context itself is uninitialized string of max+1 zeroes)
	pmCode := createCode(
		//vm.PUSH1, 1, vm.PUSH0, vm.RETURN,
		copyToMemory(core.PackValidationData(core.MAGIC_VALUE_PAYMASTER, 0, 0), 0),
		copyToMemory(asBytes32(64), 32),
		copyToMemory(asBytes32(core.PAYMASTER_MAX_CONTEXT_SIZE+1), 64),
		push(core.PAYMASTER_MAX_CONTEXT_SIZE+96+1), vm.PUSH0, vm.RETURN)

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), pmCode, DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: 1000000000,
		PaymasterGas:  1000000000,
		GasFeeCap:     big.NewInt(1000000000),
		Paymaster:     &DEFAULT_PAYMASTER,
	}, "paymaster context too large")
}

func TestPaymasterValidation_ok(t *testing.T) {
	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), returnWithData(paymasterReturnValue(core.MAGIC_VALUE_PAYMASTER, 0, 0, []byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGas: 1000000000,
		PaymasterGas:  1000000000,
		GasFeeCap:     big.NewInt(1000000000),
		Paymaster:     &DEFAULT_PAYMASTER,
	}, "ok")
}