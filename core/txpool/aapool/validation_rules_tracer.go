package aapool

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"math/big"
)

// ValidationRulesTracer implements vm.EVMLogger interface in order to check the
// AA transaction validation frame compliance with ERC-7562
type ValidationRulesTracer struct{}

func (v *ValidationRulesTracer) CaptureTxStart(gasLimit uint64) {
	log.Error("ALEXF TRACER CaptureTxStart!")
	//TODO implement me
}

func (v *ValidationRulesTracer) CaptureTxEnd(restGas uint64) {
	log.Error("ALEXF TRACER CaptureTxEnd!")
	//TODO implement me
}

func (v *ValidationRulesTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
	log.Error("ALEXF TRACER CaptureStart!")
	//TODO implement me
}

func (v *ValidationRulesTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	log.Error("ALEXF TRACER CaptureEnd!")
	//TODO implement me
}

func (v *ValidationRulesTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	log.Error(fmt.Sprintf("ALEXF TRACER CaptureEnter OP: %s", typ.String()))
	//TODO implement me
}

func (v *ValidationRulesTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	log.Error("ALEXF TRACER CaptureExit!")
	//TODO implement me
}

func (v *ValidationRulesTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	log.Error(fmt.Sprintf("ALEXF TRACER CaptureState OP: %s", op.String()))
	//TODO implement me
}

func (v *ValidationRulesTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, depth int, err error) {
	log.Error(fmt.Sprintf("ALEXF TRACER CaptureFault OP: %s", op.String()))
	//TODO implement me
}
