// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package native

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
	"math/big"
	"strings"
)

//go:generate go run github.com/fjl/gencodec -type callFrame -field-override callFrameMarshaling -out gen_callframe_json.go

func init() {
	tracers.DefaultDirectory.Register("erc7562Tracer", newErc7562Tracer, false)
}

type callFrameWithOpcodes struct {
	callFrame
	AccessedSlots     accessedSlots          `json:"accessedSlots"`
	ExtCodeAccessInfo []common.Address       `json:"extCodeAccessInfo"`
	DeployedContracts []common.Address       `json:"deployedContracts"`
	UsedOpcodes       map[vm.OpCode]bool     `json:"usedOpcodes"`
	GasObserved       bool                   `json:"gasObserved"`
	ContractSize      map[common.Address]int `json:"contractSize"`
	OutOfGas          bool                   `json:"outOfGas"`
	Calls             []callFrameWithOpcodes `json:"calls,omitempty" rlp:"optional"`
}

// TODO: I suggest that we provide an `[]string` for all of these fields. Doing it for `Reads` as an example here.
type accessedSlots struct {
	Reads           map[string][]string `json:"reads"`
	Writes          map[string]uint64   `json:"writes"`
	TransientReads  map[string]uint64   `json:"transientReads"`
	TransientWrites map[string]uint64   `json:"transientWrites"`
}

type erc7562Tracer struct {
	callTracer
	env *tracing.VMContext

	lastOp               vm.OpCode
	callstackWithOpcodes []callFrameWithOpcodes
	lastThreeOpCodes     []vm.OpCode
	Keccak               []hexutil.Bytes `json:"keccak"`
}

// newCallTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func newErc7562Tracer(ctx *tracers.Context, cfg json.RawMessage /*, chainConfig *params.ChainConfig*/) (*tracers.Tracer, error) {
	t, err := newErc7562TracerObject(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: t.OnTxStart,
			OnOpcode:  t.OnOpcode,
			OnTxEnd:   t.OnTxEnd,
			OnEnter:   t.OnEnter,
			OnExit:    t.OnExit,
			OnLog:     t.OnLog,
		},
		GetResult: t.GetResult,
		Stop:      t.Stop,
	}, nil
}

func newErc7562TracerObject(ctx *tracers.Context, cfg json.RawMessage) (*erc7562Tracer, error) {
	var config callTracerConfig
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}
	}
	// First callframe contains tx context info
	// and is populated on start and end.
	return &erc7562Tracer{callstackWithOpcodes: make([]callFrameWithOpcodes, 0, 1), callTracer: callTracer{config: config}}, nil
}

func (t *erc7562Tracer) OnTxStart(env *tracing.VMContext, tx *types.Transaction, from common.Address) {
	t.env = env
	t.gasLimit = tx.Gas()
}

// OnEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *erc7562Tracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	t.depth = depth
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}

	toCopy := to
	call := callFrameWithOpcodes{
		callFrame: callFrame{
			Type:  vm.OpCode(typ),
			From:  from,
			To:    &toCopy,
			Input: common.CopyBytes(input),
			Gas:   gas,
			Value: value},
		AccessedSlots: accessedSlots{
			Reads:           map[string][]string{},
			Writes:          map[string]uint64{},
			TransientReads:  map[string]uint64{},
			TransientWrites: map[string]uint64{},
		},
		UsedOpcodes:  make(map[vm.OpCode]bool, 3),
		ContractSize: make(map[common.Address]int, 1),
	}
	if depth == 0 {
		call.Gas = t.gasLimit
	}
	t.callstackWithOpcodes = append(t.callstackWithOpcodes, call)
}

func (t *erc7562Tracer) captureEnd(output []byte, gasUsed uint64, err error, reverted bool) {
	if len(t.callstackWithOpcodes) != 1 {
		return
	}
	t.callstackWithOpcodes[0].processOutput(output, err, reverted)
}

// OnExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *erc7562Tracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if depth == 0 {
		t.captureEnd(output, gasUsed, err, reverted)
		return
	}

	t.depth = depth - 1
	if t.config.OnlyTopCall {
		return
	}

	size := len(t.callstackWithOpcodes)
	if size <= 1 {
		return
	}
	// Pop call.
	call := t.callstackWithOpcodes[size-1]
	t.callstackWithOpcodes = t.callstackWithOpcodes[:size-1]
	size -= 1

	call.GasUsed = gasUsed
	call.processOutput(output, err, reverted)
	// Nest call into parent.
	t.callstackWithOpcodes[size-1].Calls = append(t.callstackWithOpcodes[size-1].Calls, call)
}

func (t *erc7562Tracer) OnTxEnd(receipt *types.Receipt, err error) {
	// Error happened during tx validation.
	if err != nil {
		return
	}
	log.Error("WTF is receipt", receipt)
	t.callstackWithOpcodes[0].GasUsed = receipt.GasUsed
	if t.config.WithLog {
		// Logs are not emitted when the call fails
		clearFailedLogs(&t.callstackWithOpcodes[0].callFrame, false)
	}
}

func (t *erc7562Tracer) OnLog(log *types.Log) {
	// Only logs need to be captured via opcode processing
	if !t.config.WithLog {
		return
	}
	// Avoid processing nested calls when only caring about top call
	if t.config.OnlyTopCall && t.depth > 0 {
		return
	}
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}
	l := callLog{
		Address:  log.Address,
		Topics:   log.Topics,
		Data:     log.Data,
		Position: hexutil.Uint(len(t.callstackWithOpcodes[len(t.callstackWithOpcodes)-1].Calls)),
	}
	t.callstackWithOpcodes[len(t.callstackWithOpcodes)-1].Logs = append(t.callstackWithOpcodes[len(t.callstackWithOpcodes)-1].Logs, l)
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *erc7562Tracer) GetResult() (json.RawMessage, error) {
	if len(t.callstackWithOpcodes) != 1 {
		return nil, errors.New("incorrect number of top-level calls")
	}

	res, err := json.Marshal(t.callstackWithOpcodes[0])
	if err != nil {
		return nil, err
	}
	return res, t.reason
}

func (t *erc7562Tracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	opcode := vm.OpCode(op)

	stackSize := len(scope.StackData())
	stackTop3 := partialStack{}
	for i := 0; i < 3 && i < stackSize; i++ {
		stackTop3 = append(stackTop3, peepStack(scope.StackData(), i))
	}
	t.lastThreeOpCodes = append(t.lastThreeOpCodes, opcode)
	if len(t.lastThreeOpCodes) > 3 {
		t.lastThreeOpCodes = t.lastThreeOpCodes[1:]
	}
	//log.Error("WTF 2", pc, opcode.String())

	size := len(t.callstackWithOpcodes)
	currentCallFrame := t.callstackWithOpcodes[size-1]
	//log.Error("WTF 3")
	t.detectOutOfGas(gas, cost, opcode, currentCallFrame)
	//log.Error("WTF 4")
	t.handleExtOpcodes(opcode, currentCallFrame, stackTop3)
	//log.Error("WTF 5")
	t.handleAccessedContractSize(opcode, scope, currentCallFrame)
	//log.Error("WTF 6")
	t.handleGasObserved(opcode, currentCallFrame)
	//log.Error("WTF 7")
	t.storeUsedOpcode(opcode, currentCallFrame)
	//log.Error("WTF 8")
	t.handleStorageAccess(opcode, scope, currentCallFrame)
	//log.Error("WTF 9")
	t.storeKeccak(opcode, scope)
	//log.Error("WTF 10")
	t.lastOp = opcode
	//log.Error("WTF END??", pc)
}

func (t *erc7562Tracer) handleGasObserved(opcode vm.OpCode, currentCallFrame callFrameWithOpcodes) {
	// [OP-012]
	pendingGasObserved := t.lastOp == vm.GAS && !strings.Contains(opcode.String(), "CALL")
	if pendingGasObserved {
		currentCallFrame.GasObserved = true
	}
}

func (t *erc7562Tracer) storeUsedOpcode(opcode vm.OpCode, currentCallFrame callFrameWithOpcodes) {
	// ignore "unimportant" opcodes
	if opcode != vm.GAS && !isAllowedOpcodeAfterGAS(opcode) {
		currentCallFrame.UsedOpcodes[opcode] = true
	}
}

func (t *erc7562Tracer) handleStorageAccess(opcode vm.OpCode, scope tracing.OpContext, currentCallFrame callFrameWithOpcodes) {
	if opcode == vm.SLOAD || opcode == vm.SSTORE || opcode == vm.TLOAD || opcode == vm.TSTORE {
		slot := common.BytesToHash(peepStack(scope.StackData(), 0).Bytes())
		slotHex := slot.Hex()
		addr := scope.Address()

		if opcode == vm.SLOAD {
			// read slot values before this UserOp was created
			// (so saving it if it was written before the first read)
			_, rOk := currentCallFrame.AccessedSlots.Reads[slotHex]
			_, wOk := currentCallFrame.AccessedSlots.Writes[slotHex]
			if !rOk && !wOk {
				currentCallFrame.AccessedSlots.Reads[slotHex] = append(currentCallFrame.AccessedSlots.Reads[slotHex], t.env.StateDB.GetState(addr, slot).Hex())
			}
		} else if opcode == vm.SSTORE {
			incrementCount(currentCallFrame.AccessedSlots.Writes, slotHex)
		} else if opcode == vm.TLOAD {
			incrementCount(currentCallFrame.AccessedSlots.TransientReads, slotHex)
		} else if opcode == vm.TSTORE {
			incrementCount(currentCallFrame.AccessedSlots.TransientWrites, slotHex)
		}
	}
}

func (t *erc7562Tracer) storeKeccak(opcode vm.OpCode, scope tracing.OpContext) {
	if opcode == vm.KECCAK256 {
		dataOffset := peepStack(scope.StackData(), 0).Uint64()
		dataLength := peepStack(scope.StackData(), 1).Uint64()
		memory := scope.MemoryData()
		keccak := make([]byte, dataLength)
		copy(keccak, memory[dataOffset:dataOffset+dataLength])
		t.Keccak = append(t.Keccak, keccak)
	}
}

//func (t *erc7562Tracer) handleLogs(opcode vm.OpCode, scope tracing.OpContext) {
//	if opcode == vm.LOG0 || opcode == vm.LOG1 || opcode == vm.LOG2 || opcode == vm.LOG3 || opcode == vm.LOG4 {
//		count := int(opcode - vm.LOG0)
//		ofs := peepStack(scope.StackData(), 0)
//		len := peepStack(scope.StackData(), 1)
//		memory := scope.MemoryData()
//		topics := []hexutil.Bytes{}
//		for i := 0; i < count; i++ {
//			topics = append(topics, peepStack(scope.StackData(), 2+i).Bytes())
//			//topics = append(topics, scope.Stack.Back(2+i).Bytes())
//		}
//		log := make([]byte, len.Uint64())
//		copy(log, memory[ofs.Uint64():ofs.Uint64()+len.Uint64()])
//		t.Logs = append(t.Logs, &logsItem{
//			Data:  log,
//			Topic: topics,
//		})
//	}
//}

func (t *erc7562Tracer) detectOutOfGas(gas uint64, cost uint64, opcode vm.OpCode, currentCallFrame callFrameWithOpcodes) {
	if gas < cost || (opcode == vm.SSTORE && gas < 2300) {
		currentCallFrame.OutOfGas = true
	}
}

// TODO: rewrite using byte opcode values, without relying on string manipulations
func (t *erc7562Tracer) handleExtOpcodes(opcode vm.OpCode, currentCallFrame callFrameWithOpcodes, stackTop3 partialStack) {
	if strings.HasPrefix(opcode.String(), "EXT") {
		addr := common.HexToAddress(stackTop3[0].Hex())
		ops := []string{}
		for _, item := range t.lastThreeOpCodes {
			ops = append(ops, item.String())
		}
		last3OpcodeStr := strings.Join(ops, ",")

		// only store the last EXTCODE* opcode per address - could even be a boolean for our current use-case
		// [OP-051]
		if !strings.Contains(last3OpcodeStr, ",EXTCODESIZE,ISZERO") {
			currentCallFrame.ExtCodeAccessInfo = append(currentCallFrame.ExtCodeAccessInfo, addr)
		}
	}
}
func (t *erc7562Tracer) handleAccessedContractSize(opcode vm.OpCode, scope tracing.OpContext, currentCallFrame callFrameWithOpcodes) {
	// [OP-041]
	if isEXTorCALL(opcode) {
		n := 0
		if !strings.HasPrefix(opcode.String(), "EXT") {
			n = 1
		}
		addr := common.BytesToAddress(peepStack(scope.StackData(), n).Bytes())
		if _, ok := currentCallFrame.ContractSize[addr]; !ok && !isAllowedPrecompile(addr) {
			currentCallFrame.ContractSize[addr] = len(t.env.StateDB.GetCode(addr))
		}
	}
}

func peepStack(stackData []uint256.Int, n int) *uint256.Int {
	return &stackData[len(stackData)-n-1]
}

func isEXTorCALL(opcode vm.OpCode) bool {
	return strings.HasPrefix(opcode.String(), "EXT") ||
		opcode == vm.CALL ||
		opcode == vm.CALLCODE ||
		opcode == vm.DELEGATECALL ||
		opcode == vm.STATICCALL
}

func isAllowedOpcodeAfterGAS(opcode vm.OpCode) bool {
	if (opcode >= vm.DUP1 && opcode <= vm.DUP16) || (opcode >= vm.SWAP1 && opcode <= vm.SWAP16) || (opcode >= vm.PUSH0 && opcode <= vm.PUSH32) {
		return true
	}
	switch opcode {
	case
		vm.POP, vm.ADD, vm.SUB, vm.MUL, vm.DIV, vm.EQ, vm.LT, vm.GT, vm.SLT, vm.SGT,
		vm.SHL, vm.SHR, vm.AND, vm.OR, vm.NOT, vm.ISZERO:
		return true
	}
	return false
}

// not using 'isPrecompiled' to only allow the ones defined by the ERC-7562 as stateless precompiles
// [OP-062]
func isAllowedPrecompile(addr common.Address) bool {
	addrInt := addr.Big()
	return addrInt.Cmp(big.NewInt(0)) == 1 && addrInt.Cmp(big.NewInt(10)) == -1
}

func incrementCount(m map[string]uint64, k string) {
	if _, ok := m[k]; !ok {
		m[k] = 0
	}
	m[k]++
}
