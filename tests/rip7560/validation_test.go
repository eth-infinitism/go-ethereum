package rip7560

import (
	"context"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/tests"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

const PREDEPLOYED_SENDER = "0xed0a7aabc745fe5d8bc6ad625c767df86044d049"

type testContext struct {
	genesisAlloc types.GenesisAlloc
	t            *testing.T
	chainContext *ethapi.ChainContext
	config       *params.ChainConfig
	gaspool      *core.GasPool
	genesisBlock *types.Block
}

func newTestContext(t *testing.T) *testContext {
	genesisAlloc := types.GenesisAlloc{}
	json, err := os.ReadFile("./testdata/prep.json")
	if err != nil {
		panic(err)
	}
	err = genesisAlloc.UnmarshalJSON(json)
	if err != nil {
		panic(err)
	}

	genesis := &core.Genesis{
		Config: params.TestChainConfig,
		Alloc:  genesisAlloc,
	}
	genesisBlock := genesis.ToBlock()
	gaspool := new(core.GasPool).AddGas(genesisBlock.GasLimit())

	//TODO: fill some mock backend...
	var backend ethapi.Backend

	return &testContext{
		t:            t,
		genesisAlloc: genesisAlloc,
		chainContext: ethapi.NewChainContext(context.TODO(), backend),
		config:       params.SepoliaChainConfig,
		genesisBlock: genesisBlock,
		gaspool:      gaspool,
	}
}

func (tt *testContext) withCode(addr string, code []byte, balance int64) *testContext {
	if len(code) == 0 {
		tt.genesisAlloc[common.HexToAddress(addr)] = types.Account{
			Balance: big.NewInt(balance),
		}
	} else {
		tt.genesisAlloc[common.HexToAddress(addr)] = types.Account{
			Code:    code,
			Balance: big.NewInt(balance),
		}
	}
	return tt
}

func TestValidation_OOG(t *testing.T) {
	validatePhase(newTestContext(t), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000),
		GasFeeCap:     big.NewInt(1000000000),
	}, "out of gas")
}

func TestValidation_ok(t *testing.T) {
	validatePhase(newTestContext(t), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000000),
		GasFeeCap:     big.NewInt(1000000000),
	}, "")
}

func TestValidation_account_revert(t *testing.T) {
	validatePhase(newTestContext(t).withCode(PREDEPLOYED_SENDER, []byte{
		byte(vm.PUSH1), 0, byte(vm.DUP1), byte(vm.REVERT),
	}, 0), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000000),
		GasFeeCap:     big.NewInt(1000000000),
	}, "execution reverted")
}

func TestValidation_account_no_return_value(t *testing.T) {
	validatePhase(newTestContext(t).withCode(PREDEPLOYED_SENDER, []byte{
		byte(vm.PUSH1), 0, byte(vm.DUP1), byte(vm.RETURN),
	}, 0), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000000),
		GasFeeCap:     big.NewInt(1000000000),
	}, "invalid account return data length")
}

func TestValidation_account_wrong_return_value(t *testing.T) {
	validatePhase(newTestContext(t).withCode(PREDEPLOYED_SENDER, []byte{
		byte(vm.PUSH1), 32, byte(vm.PUSH1), 0, byte(vm.RETURN),
	}, 0), types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000000),
		GasFeeCap:     big.NewInt(1000000000),
	}, "account did not return correct MAGIC_VALUE")
}

func validatePhase(t *testContext, aatx types.Rip7560AccountAbstractionTx, expectedErr string) {

	if aatx.Sender == nil {
		//pre-deployed sender account
		Sender := common.HexToAddress(PREDEPLOYED_SENDER)
		aatx.Sender = &Sender
	}
	tx := types.NewTx(&aatx)

	var state = tests.MakePreState(rawdb.NewMemoryDatabase(), t.genesisAlloc, false, rawdb.HashScheme)
	defer state.Close()

	_, err := core.ApplyRip7560ValidationPhases(t.config, t.chainContext, &common.Address{}, t.gaspool, state.StateDB, t.genesisBlock.Header(), tx, vm.Config{})
	// err string or empty if nil
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	if errStr != expectedErr {
		t.t.Errorf("ApplyRip7560ValidationPhases() got '%v', want '%v'", err, expectedErr)
	}
}

//test failure on non-rip7560

//IntrinsicGas: for validation frame, should return the max possible gas.
// - execution should be "free" (and refund the excess)
// geth increment nonce before "call" our validation frame. (in ApplyMessage)
