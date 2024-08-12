package tracers

import (
	"context"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rpc"
	"math/big"
	"time"
)

//  note: revertError code is copied here from the 'ethapi' package

// revertError is an API error that encompasses an EVM revert with JSON error
// code and a binary data blob.
type validationRevertError struct {
	error
	reason string // revert reason hex encoded
}

func (v *validationRevertError) ErrorData() interface{} {
	return v.reason
}

// newValidationRevertError creates a revertError instance with the provided revert data.
func newValidationRevertError(vpr *core.ValidationPhaseResult) *validationRevertError {
	errorMessage := fmt.Sprintf("validation phase reverted in contract %s", vpr.RevertEntityName)
	// TODO: use "vm.ErrorX" for RIP-7560 specific errors as well!
	err := errors.New(errorMessage)

	reason, errUnpack := abi.UnpackRevert(vpr.RevertReason)
	if errUnpack == nil {
		err = fmt.Errorf("%w: %v", err, reason)
	}
	return &validationRevertError{
		error:  err,
		reason: hexutil.Encode(vpr.RevertReason),
	}
}

// Rip7560API is the collection of tracing APIs exposed over the private debugging endpoint.
type Rip7560API struct {
	backend Backend
}

func NewRip7560API(backend Backend) *Rip7560API {
	return &Rip7560API{backend: backend}
}

// TraceRip7560Validation mostly copied from 'tracers/api.go' file
func (api *Rip7560API) TraceRip7560Validation(
	ctx context.Context,
	args ethapi.TransactionArgs,
	blockNrOrHash rpc.BlockNumberOrHash,
	config *TraceCallConfig,
) (interface{}, error) {
	number, _ := blockNrOrHash.Number()
	block, err := api.blockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	reexec := defaultTraceReexec
	statedb, release, err := api.backend.StateAtBlock(ctx, block, reexec, nil, true, false)
	if err != nil {
		return nil, err
	}
	defer release()

	vmctx := core.NewEVMBlockContext(block.Header(), api.chainContext(ctx), nil)
	if err := args.CallDefaults(api.backend.RPCGasCap(), vmctx.BaseFee, api.backend.ChainConfig().ChainID); err != nil {
		return nil, err
	}
	var (
		//msg         = args.ToMessage(vmctx.BaseFee)
		tx          = args.ToTransaction()
		traceConfig *TraceConfig
	)
	if config != nil {
		traceConfig = &config.TraceConfig
	}
	traceResult, vpr, err := api.traceTx(ctx, tx, new(Context), block, vmctx, statedb, traceConfig)
	if err != nil {
		return nil, err
	}
	if vpr != nil && vpr.RevertReason != nil {
		return nil, newValidationRevertError(vpr)
	}
	return traceResult, err
}

//////// copy-pasted code

// blockByNumber is the wrapper of the chain access function offered by the backend.
// It will return an error if the block is not found.
func (api *Rip7560API) blockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {
	block, err := api.backend.BlockByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, fmt.Errorf("block #%d not found", number)
	}
	return block, nil
}

// chainContext constructs the context reader which is used by the evm for reading
// the necessary chain context.
func (api *Rip7560API) chainContext(ctx context.Context) core.ChainContext {
	return ethapi.NewChainContext(ctx, api.backend)
}

func (api *Rip7560API) traceTx(ctx context.Context, tx *types.Transaction, txctx *Context, block *types.Block, vmctx vm.BlockContext, statedb *state.StateDB, config *TraceConfig) (interface{}, *core.ValidationPhaseResult, error) {
	var (
		tracer  *Tracer
		err     error
		timeout = defaultTraceTimeout
		//usedGas uint64
	)
	if config == nil {
		config = &TraceConfig{}
	}
	// Default tracer is the struct logger
	//if config.Tracer == nil {
	//	logger := logger.NewStructLogger(config.Config)
	//	tracer = &Tracer{
	//		Hooks:     logger.Hooks(),
	//		GetResult: logger.GetResult,
	//		Stop:      logger.Stop,
	//	}
	//} else {
	tracer, err = DefaultDirectory.New("rip7560Validation", txctx, config.TracerConfig)
	//	if err != nil {
	//		return nil, err
	//	}
	//}
	vmenv := vm.NewEVM(vmctx, vm.TxContext{GasPrice: big.NewInt(0)}, statedb, api.backend.ChainConfig(), vm.Config{Tracer: tracer.Hooks, NoBaseFee: true})
	statedb.SetLogger(tracer.Hooks)

	// Define a meaningful timeout of a single transaction trace
	if config.Timeout != nil {
		if timeout, err = time.ParseDuration(*config.Timeout); err != nil {
			return nil, nil, err
		}
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	go func() {
		<-deadlineCtx.Done()
		if errors.Is(deadlineCtx.Err(), context.DeadlineExceeded) {
			tracer.Stop(errors.New("execution timeout"))
			// Stop evm execution. Note cancellation is not necessarily immediate.
			vmenv.Cancel()
		}
	}()
	defer cancel()

	// Call Prepare to clear out the statedb access list
	statedb.SetTxContext(txctx.TxHash, txctx.TxIndex)
	gp := new(core.GasPool).AddGas(10000000)

	// TODO: this is added to allow our bundler checking the 'TraceValidation' API is supported on Geth
	if tx.Rip7560TransactionData().Sender.Cmp(common.HexToAddress("0x0000000000000000000000000000000000000000")) == 0 {
		result, err := tracer.GetResult()
		return result, nil, err
	}

	vpr, err := core.ApplyRip7560ValidationPhases(api.backend.ChainConfig(), api.chainContext(ctx), nil, gp, statedb, block.Header(), tx, vmenv.Config)
	if err != nil {
		return nil, nil, fmt.Errorf("tracing failed: %w", err)
	}
	result, err := tracer.GetResult()
	return result, vpr, err
}
