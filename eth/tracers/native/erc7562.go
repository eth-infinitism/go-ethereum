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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"math/big"
	"regexp"
	"strings"
)

//go:generate go run github.com/fjl/gencodec -type callFrame -field-override callFrameMarshaling -out gen_callframe_json.go

func init() {
	tracers.DefaultDirectory.Register("callTracerWithOpcodes", newCallTracerWithOpcodes, false)
}

type callFrameWithOpcodes struct {
	callFrame
	AccessedSlots     *accessedSlots         `json:"accessedSlots"`
	ExtCodeAccessInfo []common.Address       `json:"extCodeAccessInfo"`
	DeployedContracts []common.Address       `json:"deployedContracts"`
	UsedOpcodes       map[string]bool        `json:"usedOpcodes"`
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

type callTracerWithOpcodes struct {
	callTracer
	env *tracing.VMContext

	allowedOpcodeRegex *regexp.Regexp
	lastOp             string
	callstack          []callFrameWithOpcodes
	lastThreeOpCodes   []string
	Keccak             []hexutil.Bytes `json:"keccak"`
}

// newCallTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func newCallTracerWithOpcodes(ctx *tracers.Context, cfg json.RawMessage, chainConfig *params.ChainConfig) (*tracers.Tracer, error) {
	t, err := newCallTracerObjectWithOpcodes(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: t.OnTxStart,
			OnTxEnd:   t.OnTxEnd,
			OnEnter:   t.OnEnter,
			OnExit:    t.OnExit,
			OnLog:     t.OnLog,
		},
		GetResult: t.GetResult,
		Stop:      t.Stop,
	}, nil
}

func newCallTracerObjectWithOpcodes(ctx *tracers.Context, cfg json.RawMessage) (*callTracer, error) {
	var config callTracerConfig
	if err := json.Unmarshal(cfg, &config); err != nil {
		return nil, err
	}
	// First callframe contains tx context info
	// and is populated on start and end.
	return &callTracer{callstack: make([]callFrame, 0, 1), config: config}, nil
}

// OnEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *callTracerWithOpcodes) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	t.depth = depth
	if t.config.OnlyTopCall && depth > 0 {
		return
	}
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}

	toCopy := to
	_accessedSlots := &accessedSlots{
		Reads:           map[string][]string{},
		Writes:          map[string]uint64{},
		TransientReads:  map[string]uint64{},
		TransientWrites: map[string]uint64{},
	}
	_callFrame := callFrame{
		Type:  vm.OpCode(typ),
		From:  from,
		To:    &toCopy,
		Input: common.CopyBytes(input),
		Gas:   gas,
		Value: value}
	call := callFrameWithOpcodes{
		callFrame:     _callFrame,
		AccessedSlots: _accessedSlots,
		UsedOpcodes:   make(map[string]bool),
	}
	if depth == 0 {
		call.Gas = t.gasLimit
	}
	t.callstack = append(t.callstack, call)
}

// TODO: Why is this type even needed?
type partialStack = []*uint256.Int

func (t *callTracerWithOpcodes) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	opcode := vm.OpCode(op).String()

	stackSize := len(scope.StackData())
	stackTop3 := partialStack{}
	for i := 0; i < 3 && i < stackSize; i++ {
		stackTop3 = append(stackTop3, stackBack(scope.StackData(), i))
	}
	t.lastThreeOpCodes = append(t.lastThreeOpCodes, opcode)
	if len(t.lastThreeOpCodes) > 3 {
		t.lastThreeOpCodes = t.lastThreeOpCodes[1:]
	}

	size := len(t.callstack)
	call := t.callstack[size-1]

	if gas < cost || (opcode == "SSTORE" && gas < 2300) {
		call.OutOfGas = true
	}

	if opcode == "REVERT" || opcode == "RETURN" {
		// exit() is not called on top-level return/revert, so we reconstruct it from opcode
		if depth == 1 {
			// TODO: uncomment and fix with StackBack
			//ofs := scope.Stack.Back(0).ToBig().Int64()
			//len := scope.Stack.Back(1).ToBig().Int64()
			//data := scope.Memory.GetCopy(ofs, len)
			//b.Calls = append(b.Calls, &callsItem{
			//	Type:    opcode,
			//	GasUsed: 0,
			//	Data:    data,
			//})
		}
		// NOTE: flushing all history after RETURN
		//b.lastThreeOpCodes = []*lastThreeOpCodesItem{}
	}

	// not pasting the new "entryPointCall" detection here - not necessary for 7560

	//var lastOpInfo *lastThreeOpCodesItem
	//if len(b.lastThreeOpCodes) >= 2 {
	//	lastOpInfo = b.lastThreeOpCodes[len(b.lastThreeOpCodes)-2]
	//}
	// store all addresses touched by EXTCODE* opcodes
	if strings.HasPrefix(opcode, "EXT") {
		addr := common.HexToAddress(stackTop3[0].Hex())
		ops := []string{}
		for _, item := range t.lastThreeOpCodes {
			ops = append(ops, item)
		}
		last3OpcodeStr := strings.Join(ops, ",")

		// only store the last EXTCODE* opcode per address - could even be a boolean for our current use-case
		// [OP-051]
		if !strings.Contains(last3OpcodeStr, ",EXTCODESIZE,ISZERO") {
			call.ExtCodeAccessInfo = append(call.ExtCodeAccessInfo, addr)
		}
	}

	// [OP-041]
	if isEXTorCALL(opcode) {
		n := 0
		if !strings.HasPrefix(opcode, "EXT") {
			n = 1
		}
		addr := common.BytesToAddress(stackBack(scope.StackData(), n).Bytes())

		if _, ok := call.ContractSize[addr]; !ok && !isAllowedPrecompile(addr) {
			call.ContractSize[addr] = len(t.env.StateDB.GetCode(addr))
		}
	}

	// [OP-012]
	if t.lastOp == "GAS" && !strings.Contains(opcode, "CALL") {
		call.UsedOpcodes["GAS"] = true
	}
	// ignore "unimportant" opcodes
	if opcode != "GAS" && !t.allowedOpcodeRegex.MatchString(opcode) {
		call.UsedOpcodes[opcode] = true
	}
	t.lastOp = opcode

	if opcode == "SLOAD" || opcode == "SSTORE" || opcode == "TLOAD" || opcode == "TSTORE" {
		slot := common.BytesToHash(stackBack(scope.StackData(), 0).Bytes())
		slotHex := slot.Hex()
		addr := scope.Address()

		if opcode == "SLOAD" {
			// read slot values before this UserOp was created
			// (so saving it if it was written before the first read)
			_, rOk := call.AccessedSlots.Reads[slotHex]
			_, wOk := call.AccessedSlots.Writes[slotHex]
			if !rOk && !wOk {
				call.AccessedSlots.Reads[slotHex] = append(call.AccessedSlots.Reads[slotHex], t.env.StateDB.GetState(addr, slot).Hex())
			}
		} else if opcode == "SSTORE" {
			incrementCount(call.AccessedSlots.Writes, slotHex)
		} else if opcode == "TLOAD" {
			incrementCount(call.AccessedSlots.TransientReads, slotHex)
		} else if opcode == "TSTORE" {
			incrementCount(call.AccessedSlots.TransientWrites, slotHex)
		}
	}

	if opcode == "KECCAK256" {
		// TODO: uncomment and fix with StackBack
		// collect keccak on 64-byte blocks
		ofs := stackBack(scope.StackData(), 0)
		len := stackBack(scope.StackData(), 1)
		memory := scope.MemoryData()
		// currently, solidity uses only 2-word (6-byte) for a key. this might change..still, no need to
		// return too much
		if len.Uint64() > 20 && len.Uint64() < 512 {
			keccak := make([]byte, len.Uint64())
			copy(keccak, memory[ofs.Uint64():ofs.Uint64()+len.Uint64()])
			t.Keccak = append(t.Keccak, keccak)
		}
	}
}

// StackBack returns the n-th item in stack
func stackBack(stackData []uint256.Int, n int) *uint256.Int {
	return &stackData[len(stackData)-n-1]
}

func isEXTorCALL(opcode string) bool {
	return strings.HasPrefix(opcode, "EXT") ||
		opcode == "CALL" ||
		opcode == "CALLCODE" ||
		opcode == "DELEGATECALL" ||
		opcode == "STATICCALL"
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
