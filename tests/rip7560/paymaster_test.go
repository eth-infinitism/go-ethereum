package rip7560

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"math/big"
	"testing"
)

var DEFAULT_PAYMASTER = common.HexToAddress("0xaaaaaaaaaabbbbbbbbbbccccccccccdddddddddd")

func TestPaymasterValidationFailure_nobalance(t *testing.T) {

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(vm.PUSH0, vm.DUP1, vm.REVERT), 1), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit: 1000000000,
		GasFeeCap:          big.NewInt(1000000000),
		Paymaster:          &DEFAULT_PAYMASTER,
	}, "insufficient funds for gas * price + value: address 0xaaAaaAAAAAbBbbbbBbBBCCCCcCCCcCdddDDDdddd have 1 want 1000000000000000000")
}

func TestPaymasterValidationFailure_oog(t *testing.T) {

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(vm.PUSH0, vm.DUP1, vm.REVERT), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit: 1000000000,
		GasFeeCap:          big.NewInt(1000000000),
		Paymaster:          &DEFAULT_PAYMASTER,
	}, "gas limit reached")
}
func TestPaymasterValidationFailure_revert(t *testing.T) {

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createCode(revertWithData([]byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1_000_000,
		GasFeeCap:                   big.NewInt(1000000000),
		Paymaster:                   &DEFAULT_PAYMASTER,
		PaymasterValidationGasLimit: 1_000_000,
	}, "execution reverted")
}

func TestPaymasterValidationFailure_wrong_callback(t *testing.T) {

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), createAccountCode(), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1_000_000,
		PaymasterValidationGasLimit: 1_000_000,
		GasFeeCap:                   big.NewInt(1000000000),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "unable to decode acceptPaymaster: got wrong method acceptAccount")
}

func TestPaymasterValidationFailure_no_callback(t *testing.T) {
	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), returnWithData(paymasterAcceptReturnValue(1, 2, []byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1_000_000,
		PaymasterValidationGasLimit: 1_000_000,
		GasFeeCap:                   big.NewInt(1000000000),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "paymaster validation did not call the EntryPoint 'acceptPaymaster' callback")
}

func TestPaymasterValidationFailure_contextTooLarge(t *testing.T) {
	//paymaster returning huge context.
	// TODO: need to generate the return data on-chain, since we can't inject 64k of code..
	//  (checked the test by modifying the max size to 5000)
	pmCode := paymasterAcceptReturnValue(0, 0, make([]byte, 7000))

	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), pmCode, DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1_000_000,
		PaymasterValidationGasLimit: 1_000_000,
		GasFeeCap:                   big.NewInt(1000000000),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "paymaster return data: context too large")
}

func TestPaymasterValidationFailure_validAfter(t *testing.T) {
	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), paymasterAcceptReturnValue(300, 200, []byte{}), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1_000_000,
		PaymasterValidationGasLimit: 1_000_000,
		GasFeeCap:                   big.NewInt(1000000000),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "RIP-7560 transaction validity not reached yet")
}

func TestPaymasterValidationFailure_validUntil(t *testing.T) {
	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), paymasterAcceptReturnValue(1, 2, []byte{}), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1_000_000,
		PaymasterValidationGasLimit: 1_000_000,
		GasFeeCap:                   big.NewInt(1000000000),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "RIP-7560 transaction validity expired")
}

func TestPaymasterValidation_ok(t *testing.T) {
	handleTransaction(newTestContextBuilder(t).withCode(DEFAULT_SENDER, createAccountCode(), 0).
		withCode(DEFAULT_PAYMASTER.String(), returnWithData(paymasterAcceptReturnValue(0, 0, []byte{})), DEFAULT_BALANCE), types.Rip7560AccountAbstractionTx{
		ValidationGasLimit:          1_000_000,
		PaymasterValidationGasLimit: 1_000_000,
		GasFeeCap:                   big.NewInt(1000000000),
		Paymaster:                   &DEFAULT_PAYMASTER,
	}, "ok")
}
