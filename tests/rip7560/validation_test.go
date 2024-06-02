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

func TestValidation_OOG(t *testing.T) {
	validatePhase(t, types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000),
		GasFeeCap:     big.NewInt(1000000000),
	}, "out of gas")
}

func TestValidation_ok(t *testing.T) {
	validatePhase(t, types.Rip7560AccountAbstractionTx{
		ValidationGas: uint64(1000000000),
		GasFeeCap:     big.NewInt(1000000000),
	}, "")
}

func validatePhase(t *testing.T, aatx types.Rip7560AccountAbstractionTx, expectedErr string) {
	Sender := common.HexToAddress("0xed0a7aabc745fe5d8bc6ad625c767df86044d049")

	if aatx.Sender == nil {
		aatx.Sender = &Sender
	}
	tx := types.NewTx(&aatx)

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
	var state = tests.MakePreState(rawdb.NewMemoryDatabase(), genesisAlloc, false, rawdb.HashScheme)
	defer state.Close()
	genesisBlock := genesis.ToBlock()
	gaspool := new(core.GasPool).AddGas(genesisBlock.GasLimit())

	//TODO: fill some mock backend...
	var backend ethapi.Backend
	chainContext := ethapi.NewChainContext(context.TODO(), backend)

	config := params.SepoliaChainConfig
	_, err = core.ApplyRip7560ValidationPhases(config, chainContext, &common.Address{}, gaspool, state.StateDB, genesisBlock.Header(), tx, vm.Config{})
	// err string or empty if nil
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	if errStr != expectedErr {
		t.Errorf("ApplyRip7560ValidationPhases() got = %v, want %v", err, expectedErr)
	}
}

//test failure on non-rip7560

//IntrinsicGas: for validation frame, should return the max possible gas.
// - execution should be "free" (and refund the excess)
// geth increment nonce before "call" our validation frame. (in ApplyMessage)
