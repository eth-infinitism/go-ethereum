package native

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/holiman/uint256"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	tracers.DefaultDirectory.Register("bundlerCollectorTracer", newBundlerCollector, false)
}

type partialStack = []*uint256.Int

type contractSizeVal struct {
	ContractSize int    `json:"contractSize"`
	Opcode       string `json:"opcode"`
}

type access struct {
	Reads           map[string]string `json:"reads"`
	Writes          map[string]uint64 `json:"writes"`
	TransientReads  map[string]uint64 `json:"transientReads"`
	TransientWrites map[string]uint64 `json:"transientWrites"`
}

type entryPointCall struct {
	TopLevelMethodSig     *hexutil.Bytes                      `json:"topLevelMethodSig"`
	TopLevelTargetAddress *common.Address                     `json:"topLevelTargetAddress"`
	Access                map[common.Address]*access          `json:"access"`
	Opcodes               map[string]uint64                   `json:"opcodes"`
	ExtCodeAccessInfo     map[common.Address]string           `json:"extCodeAccessInfo"`
	ContractSize          map[common.Address]*contractSizeVal `json:"contractSize"`
	OOG                   *bool                               `json:"oog,omitempty"`
}

type callsItem struct {
	// Common
	Type string `json:"type"`

	// Enter info
	From   *common.Address `json:"from,omitempty"`
	To     *common.Address `json:"to,omitempty"`
	Method *hexutil.Bytes  `json:"method,omitempty"`
	Value  *string         `json:"value,omitempty"`
	Gas    *uint64         `json:"gas,omitempty"`

	// Exit info
	GasUsed *uint64       `json:"gasUsed,omitempty"`
	Data    hexutil.Bytes `json:"data,omitempty"`
}

type logsItem struct {
	Data   hexutil.Bytes   `json:"data"`
	Topics []hexutil.Bytes `json:"topics"`
}

type lastThreeOpCodesItem struct {
	Opcode    string
	StackTop3 partialStack
}

type bundlerCollectorResults struct {
	CallsFromEntryPoint []*entryPointCall `json:"callsFromEntryPoint"`
	Keccak              []hexutil.Bytes   `json:"keccak"`
	Logs                []*logsItem       `json:"logs"`
	Calls               []*callsItem      `json:"calls"`
}

type bundlerCollector struct {
	env *tracing.VMContext

	CallsFromEntryPoint []*entryPointCall
	CurrentLevel        *entryPointCall
	Keccak              []hexutil.Bytes
	Calls               []*callsItem
	Logs                []*logsItem
	lastOp              string
	lastThreeOpCodes    []*lastThreeOpCodesItem
	allowedOpcodeRegex  *regexp.Regexp
	stopCollectingTopic string
	stopCollecting      bool
}

func newBundlerCollector(ctx *tracers.Context, cfg json.RawMessage) (*tracers.Tracer, error) {
	t, err := newBundlerCollectorObject(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &tracers.Tracer{
		//TODO: tracer doesn't do anything without these methods...
		Hooks: &tracing.Hooks{
			OnTxStart: t.OnTxStart,
			// OnTxEnd:   t.OnTxEnd,
			OnEnter:  t.OnEnter,
			OnOpcode: t.OnOpcode,
			OnExit:   t.OnExit,
			// OnLog:     t.OnLog,
		},
		GetResult: t.GetResult,
	}, nil
}

func newBundlerCollectorObject(ctx *tracers.Context, cfg json.RawMessage) (*bundlerCollector, error) {
	rgx, err := regexp.Compile(
		`^(DUP\d+|PUSH\d+|SWAP\d+|POP|ADD|SUB|MUL|DIV|EQ|LTE?|S?GTE?|SLT|SH[LR]|AND|OR|NOT|ISZERO)$`,
	)
	if err != nil {
		return nil, err
	}
	// event sent after all validations are done: keccak("BeforeExecution()")
	stopCollectingTopic := "0xbb47ee3e183a558b1a2ff0874b079f3fc5478b7454eacf2bfc5af2ff5878f972"

	return &bundlerCollector{
		CallsFromEntryPoint: []*entryPointCall{},
		CurrentLevel:        nil,
		Keccak:              []hexutil.Bytes{},
		Calls:               []*callsItem{},
		Logs:                []*logsItem{},
		lastOp:              "",
		lastThreeOpCodes:    []*lastThreeOpCodesItem{},
		allowedOpcodeRegex:  rgx,
		stopCollectingTopic: stopCollectingTopic,
		stopCollecting:      false,
	}, nil
}

func (b *bundlerCollector) OnTxStart(env *tracing.VMContext, tx *types.Transaction, from common.Address) {
	b.env = env
}

// GetResult returns an empty json object.
func (b *bundlerCollector) GetResult() (json.RawMessage, error) {
	//todo: cleanup last gasused, to match javascript
	b.Calls[len(b.Calls)-1].GasUsed = new(uint64)
	bcr := bundlerCollectorResults{
		CallsFromEntryPoint: b.CallsFromEntryPoint,
		Keccak:              b.Keccak,
		Logs:                b.Logs,
		Calls:               b.Calls,
	}

	r, err := json.Marshal(bcr)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (b *bundlerCollector) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if depth == 0 {
		return
	}
	op := vm.OpCode(typ)
	if b.stopCollecting {
		return
	}

	var m []byte
	if len(input) >= 4 {
		m = copySlice(input[:4])
	}
	method := (*hexutil.Bytes)(&m)

	var valueStr *string
	if value != nil {
		v := value.String()
		valueStr = &v
	}

	b.Calls = append(b.Calls, &callsItem{
		Type:   op.String(),
		From:   &from,
		To:     &to,
		Method: method,
		Gas:    nullInt(gas),
		Value:  valueStr,
	})

	if depth == 1 {

		b.CurrentLevel = &entryPointCall{
			TopLevelMethodSig:     method,
			TopLevelTargetAddress: &to,
			Access:                map[common.Address]*access{},
			Opcodes:               map[string]uint64{},
			ExtCodeAccessInfo:     map[common.Address]string{},
			ContractSize:          map[common.Address]*contractSizeVal{},
			OOG:                   nil,
		}
		b.CallsFromEntryPoint = append(b.CallsFromEntryPoint, b.CurrentLevel)
	}
}

func nullBytes(b []byte) *[]byte {
	if len(b) == 0 {
		return nil
	}
	return &b
}
func nullInt(gas uint64) *uint64 {
	if gas == 0 {
		return nil
	}
	return &gas
}

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (b *bundlerCollector) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	//if depth == 0 {
	//	return
	//}

	if depth == 1 && reverted {
		//initialize to 4-bytes:
		arr := make([]byte, 4)
		b.CurrentLevel.TopLevelMethodSig = (*hexutil.Bytes)(&arr)
	}
	if b.stopCollecting {
		return
	}

	typ := "RETURN"
	if err != nil {
		typ = "REVERT"
	}
	b.Calls = append(b.Calls, &callsItem{
		Type:    typ,
		GasUsed: nullInt(gasUsed),
		Data:    output,
	})
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (b *bundlerCollector) OnOpcode(pc uint64, opb byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {

	op := vm.OpCode(opb)
	if b.stopCollecting {
		return
	}

	if gas < cost || (op == vm.SSTORE && gas < 2300) {
		t := true
		b.CurrentLevel.OOG = &t
	}

	if opb >= 0x5f && opb <= 0x9f {
		return
	}

	opcode := op.String()

	stackSize := len(scope.StackData())
	stackTop3 := partialStack{}
	for i := 0; i < 3 && i < stackSize; i++ {
		stackTop3 = append(stackTop3, StackBack(scope.StackData(), i))
	}
	b.lastThreeOpCodes = append(b.lastThreeOpCodes, &lastThreeOpCodesItem{
		Opcode:    opcode,
		StackTop3: stackTop3,
	})
	if len(b.lastThreeOpCodes) > 3 {
		b.lastThreeOpCodes = b.lastThreeOpCodes[1:]
	}

	if opcode == "REVERT" || opcode == "RETURN" {
		//TODO: OnExit is called on these cases. so code below should be removed (and maybe add in OnExit)

		// exit() is not called on top-level return/revert, so we reconstruct it from opcode
		// if depth == 1 {
		// 	ofs := StackBack(scope.StackData(),0).ToBig().Uint64()
		// 	len := StackBack(scope.StackData(),1).ToBig().Uint64()
		// 	data := scope.Memory.GetCopy(ofs, len)
		// 	b.Calls = append(b.Calls, &callsItem{
		// 		Type:    opcode,
		// 		GasUsed: 0,
		// 		Data:    data,
		// 	})
		// }
		// NOTE: flushing all history after RETURN
		b.lastThreeOpCodes = []*lastThreeOpCodesItem{}
	}

	if depth == 1 {
		//moved to OnEnter
		//if opcode == "CALL" || opcode == "STATICCALL" {
		//	addr := common.HexToAddress(StackBack(scope.StackData(), 1).Hex())
		//
		//	ofs := StackBack(scope.StackData(), 3).ToBig().Uint64()
		//	sig := scope.MemoryData()[ofs : ofs+4]
		//	fmt.Printf("==== CALL: %s %v\n", addr.Hex(), scope.MemoryData()[ofs:ofs+10])
		//	sig = append(sig, byte(ofs>>8), byte(ofs&0xff))
		//
		//	b.CurrentLevel = &entryPointCall{
		//		ofs:                   ofs,
		//		TopLevelMethodSig:     sig,
		//		TopLevelTargetAddress: &addr,
		//		Access:                map[common.Address]*access{},
		//		Opcodes:               map[string]uint64{},
		//		ExtCodeAccessInfo:     map[common.Address]string{},
		//		ContractSize:          map[common.Address]*contractSizeVal{},
		//		OOG:                   nil,
		//	}
		//	b.CallsFromEntryPoint = append(b.CallsFromEntryPoint, b.CurrentLevel)
		//} else
		if opcode == "LOG1" && StackBack(scope.StackData(), 2).Hex() == b.stopCollectingTopic {
			b.stopCollecting = true
		}
		b.lastOp = ""
		return
	}

	var lastOpInfo *lastThreeOpCodesItem
	if len(b.lastThreeOpCodes) >= 2 {
		lastOpInfo = b.lastThreeOpCodes[len(b.lastThreeOpCodes)-2]
	}
	// store all addresses touched by EXTCODE* opcodes
	if lastOpInfo != nil && strings.HasPrefix(lastOpInfo.Opcode, "EXT") {
		addr := common.HexToAddress(lastOpInfo.StackTop3[0].Hex())
		ops := []string{}
		for _, item := range b.lastThreeOpCodes {
			ops = append(ops, item.Opcode)
		}
		last3OpcodeStr := strings.Join(ops, ",")

		// only store the last EXTCODE* opcode per address - could even be a boolean for our current use-case
		// [OP-051]
		if !strings.Contains(last3OpcodeStr, ",EXTCODESIZE,ISZERO") {
			b.CurrentLevel.ExtCodeAccessInfo[addr] = opcode
		}
	}

	// [OP-041]
	if b.isEXTorCALL(opcode) {
		n := 0
		if !strings.HasPrefix(opcode, "EXT") {
			n = 1
		}
		addr := common.BytesToAddress(StackBack(scope.StackData(), n).Bytes())

		if _, ok := b.CurrentLevel.ContractSize[addr]; !ok && !b.isAllowedPrecompile(addr) {
			b.CurrentLevel.ContractSize[addr] = &contractSizeVal{
				ContractSize: len(b.env.StateDB.GetCode(addr)),
				Opcode:       opcode,
			}
		}
	}

	// [OP-012]
	if b.lastOp == "GAS" && !strings.Contains(opcode, "CALL") {
		b.incrementCount(b.CurrentLevel.Opcodes, "GAS")
	}
	// ignore "unimportant" opcodes
	if opcode != "GAS" && !b.allowedOpcodeRegex.MatchString(opcode) {
		b.incrementCount(b.CurrentLevel.Opcodes, opcode)
	}
	b.lastOp = opcode

	if opcode == "SLOAD" || opcode == "SSTORE" || opcode == "TLOAD" || opcode == "TSTORE" {
		slot := common.BytesToHash(StackBack(scope.StackData(), 0).Bytes())
		slotHex := slot.Hex()
		addr := scope.Address()
		if _, ok := b.CurrentLevel.Access[addr]; !ok {
			b.CurrentLevel.Access[addr] = &access{
				Reads:           map[string]string{},
				Writes:          map[string]uint64{},
				TransientReads:  map[string]uint64{},
				TransientWrites: map[string]uint64{},
			}
		}
		access := *b.CurrentLevel.Access[addr]

		if opcode == "SLOAD" {
			// read slot values before this UserOp was created
			// (so saving it if it was written before the first read)
			_, rOk := access.Reads[slotHex]
			_, wOk := access.Writes[slotHex]
			if !rOk && !wOk {
				access.Reads[slotHex] = b.env.StateDB.GetState(addr, slot).Hex()
			}
		} else if opcode == "SSTORE" {
			b.incrementCount(access.Writes, slotHex)
		} else if opcode == "TLOAD" {
			b.incrementCount(access.TransientReads, slotHex)
		} else if opcode == "TSTORE" {
			b.incrementCount(access.TransientWrites, slotHex)
		}
	}

	if opcode == "KECCAK256" {
		// collect keccak on 64-byte blocks
		ofs := StackBack(scope.StackData(), 0).Uint64()
		len := StackBack(scope.StackData(), 1).Uint64()
		// currently, solidity uses only 2-word (6-byte) for a key. this might change..still, no need to
		// return too much
		if len > 20 && len < 512 {
			b.Keccak = append(b.Keccak, scope.MemoryData()[ofs:ofs+len])
		}
	} else if strings.HasPrefix(opcode, "LOG") {
		count, _ := strconv.Atoi(opcode[3:])
		ofs := StackBack(scope.StackData(), 0).Uint64()
		len := StackBack(scope.StackData(), 1).Uint64()
		topics := []hexutil.Bytes{}
		for i := 0; i < count; i++ {
			topics = append(topics, StackBack(scope.StackData(), 2+i).Bytes())
		}
		log := scope.MemoryData()[ofs : ofs+len]
		b.Logs = append(b.Logs, &logsItem{
			Data:   log,
			Topics: topics,
		})
	}
}

// StackBack returns the n-th item in stack
func StackBack(stackData []uint256.Int, n int) *uint256.Int {
	return &stackData[len(stackData)-n-1]
}

func (b *bundlerCollector) isEXTorCALL(opcode string) bool {
	return strings.HasPrefix(opcode, "EXT") ||
		opcode == "CALL" ||
		opcode == "CALLCODE" ||
		opcode == "DELEGATECALL" ||
		opcode == "STATICCALL"
}

// not using 'isPrecompiled' to only allow the ones defined by the ERC-4337 as stateless precompiles
// [OP-062]
func (b *bundlerCollector) isAllowedPrecompile(addr common.Address) bool {
	addrInt := addr.Big()
	return addrInt.Cmp(big.NewInt(0)) == 1 && addrInt.Cmp(big.NewInt(10)) == -1
}

func (b *bundlerCollector) incrementCount(m map[string]uint64, k string) {
	if _, ok := m[k]; !ok {
		m[k] = 0
	}
	m[k]++
}

func copySlice(s []byte) []byte {
	ret := make([]byte, len(s))
	copy(ret, s)
	return ret
}
