package rip7560

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/params"
	"github.com/status-im/keycard-go/hexutils"
	"math/big"
	"os"
	"testing"
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
