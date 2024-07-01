package native

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
)

func init() {
	tracers.DefaultDirectory.Register("rip7560Validation", newRip7560Tracer, false)
}

const ValidationFramesMaxCount = 3

func newRip7560Tracer(ctx *tracers.Context, cfg json.RawMessage) (*tracers.Tracer, error) {
	var config prestateTracerConfig
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}
	}
	t := &rip7560ValidationTracer{
		TraceResults: make([]stateMap, ValidationFramesMaxCount),
		UsedOpcodes:  make([]map[string]bool, ValidationFramesMaxCount),
		Created:      make([]map[common.Address]bool, ValidationFramesMaxCount),
		Deleted:      make([]map[common.Address]bool, ValidationFramesMaxCount),
	}
	return &tracers.Tracer{
		Hooks: &tracing.Hooks{
			OnTxStart: t.OnTxStart,
			OnTxEnd:   t.OnTxEnd,
			OnOpcode:  t.OnOpcode,
		},
		GetResult: t.GetResult,
		Stop:      t.Stop,
	}, nil
}

// Array fields contain of all access details of all validation frames
type rip7560ValidationTracer struct {
	env          *tracing.VMContext
	TraceResults []stateMap                `json:"traceResults"`
	UsedOpcodes  []map[string]bool         `json:"usedOpcodes"`
	Created      []map[common.Address]bool `json:"created"`
	Deleted      []map[common.Address]bool `json:"deleted"`
	// todo
	//interrupt atomic.Bool // Atomic flag to signal execution interruption
	//reason    error       // Textual reason for the interruption
}

func (t *rip7560ValidationTracer) OnTxStart(env *tracing.VMContext, tx *types.Transaction, from common.Address) {

}

func (t *rip7560ValidationTracer) OnTxEnd(receipt *types.Receipt, err error) {
}

func (t *rip7560ValidationTracer) OnOpcode(pc uint64, opcode byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	opcodeName := vm.OpCode(opcode).String()
	fmt.Printf("%s %d %d\n", opcodeName, cost, depth)
	if t.UsedOpcodes[0] == nil {
		t.UsedOpcodes[0] = make(map[string]bool)
	}
	t.UsedOpcodes[0][opcodeName] = true
}

func (t *rip7560ValidationTracer) GetResult() (json.RawMessage, error) {
	jsonResult, err := json.MarshalIndent(*t, "", "    ")
	return jsonResult, err
}

func (t *rip7560ValidationTracer) Stop(err error) {
}