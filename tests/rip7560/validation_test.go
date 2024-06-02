package rip7560

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/tests"
	"github.com/status-im/keycard-go/hexutils"
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

	chainConfig := params.AllDevChainProtocolChanges
	// probably bug in geth..
	chainConfig.PragueTime = chainConfig.CancunTime

	return &testContext{
		t:            t,
		genesisAlloc: genesisAlloc,
		chainContext: ethapi.NewChainContext(context.TODO(), backend),
		config:       chainConfig,
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
	validatePhase(newTestContext(t).withCode(PREDEPLOYED_SENDER,
		returnData(createCode(1)),
		0), types.Rip7560AccountAbstractionTx{
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

// generate the code to return the given byte array (up to 32 bytes)
func returnData(data []byte) []byte {
	//couldn't get geth to support PUSH0 ...
	datalen := len(data)
	if datalen == 0 {
		data = []byte{0}
	}

	PUSHn := byte(int(vm.PUSH0) + datalen)
	ret := createCode(PUSHn, data, vm.PUSH1, 0, vm.MSTORE, vm.PUSH1, 32, vm.PUSH1, 0, vm.RETURN)
	return ret
}

// create EVM code from OpCode, byte and []bytes
func createCode(items ...interface{}) []byte {
	var buffer bytes.Buffer

	for _, item := range items {
		switch v := item.(type) {
		case string:
			buffer.Write(hexutils.HexToBytes(v))
		case vm.OpCode:

			buffer.WriteByte(byte(v))
		case byte:

			buffer.WriteByte(v)
		case []byte:
			buffer.Write(v)
		case int8:
			buffer.WriteByte(byte(v))
		case int:
			if v >= 256 {
				panic(fmt.Errorf("int defaults to int8 (byte). int16, etc: %v", v))
			}
			buffer.WriteByte(byte(v))
		default:
			// should be a compile-time error...
			panic(fmt.Errorf("unsupported type: %T", v))
		}
	}

	return buffer.Bytes()
}

//test failure on non-rip7560

//IntrinsicGas: for validation frame, should return the max possible gas.
// - execution should be "free" (and refund the excess)
// geth increment nonce before "call" our validation frame. (in ApplyMessage)
