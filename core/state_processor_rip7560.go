package core

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"math/big"
)

type EntryPointCall struct {
	OnEnterSuper tracing.EnterHook
	Input        []byte
	From         common.Address
	err          error
}

type ValidationPhaseResult struct {
	TxIndex               int
	Tx                    *types.Transaction
	TxHash                common.Hash
	PaymasterContext      []byte
	PreCharge             *uint256.Int
	EffectiveGasPrice     *uint256.Int
	PreTransactionGasCost uint64
	ValidationRefund      uint64
	CallDataUsedGas       uint64
	NonceManagerUsedGas   uint64
	DeploymentUsedGas     uint64
	ValidationUsedGas     uint64
	PmValidationUsedGas   uint64
	SenderValidAfter      uint64
	SenderValidUntil      uint64
	PmValidAfter          uint64
	PmValidUntil          uint64
}

const (
	ExecutionStatusSuccess                   = uint64(0)
	ExecutionStatusExecutionFailure          = uint64(1)
	ExecutionStatusPostOpFailure             = uint64(2)
	ExecutionStatusExecutionAndPostOpFailure = uint64(3)
)

// ValidationPhaseError is an API error that encompasses an EVM revert with JSON error
// code and a binary data blob.
type ValidationPhaseError struct {
	error
	reason string // revert reason hex encoded

	revertEntityName *string
	frameReverted    bool
}

func (v *ValidationPhaseError) ErrorData() interface{} {
	return v.reason
}

// wrapError creates a revertError instance for validation errors not caused by an on-chain revert
func wrapError(
	innerErr error,
) *ValidationPhaseError {
	return newValidationPhaseError(innerErr, nil, nil, false)

}

// newValidationPhaseError creates a revertError instance with the provided revert data.
func newValidationPhaseError(
	innerErr error,
	revertReason []byte,
	revertEntityName *string,
	frameReverted bool,
) *ValidationPhaseError {
	var errorMessage string
	contractSubst := ""
	if revertEntityName != nil {
		contractSubst = fmt.Sprintf(" in contract %s", *revertEntityName)
	}
	if innerErr != nil {
		errorMessage = fmt.Sprintf(
			"validation phase failed%s with exception: %s",
			contractSubst,
			innerErr.Error(),
		)
	} else {
		errorMessage = fmt.Sprintf("validation phase failed%s", contractSubst)
	}
	// TODO: use "vm.ErrorX" for RIP-7560 specific errors as well!
	err := errors.New(errorMessage)

	reason, errUnpack := abi.UnpackRevert(revertReason)
	if errUnpack == nil {
		err = fmt.Errorf("%w: %v", err, reason)
	}
	return &ValidationPhaseError{
		error:  err,
		reason: hexutil.Encode(revertReason),

		frameReverted:    frameReverted,
		revertEntityName: revertEntityName,
	}
}

// HandleRip7560Transactions apply state changes of all sequential RIP-7560 transactions.
// During block building the 'skipInvalid' flag is set to False, and invalid transactions are silently ignored.
// Returns an array of included transactions.
func HandleRip7560Transactions(
	transactions []*types.Transaction,
	index int,
	statedb *state.StateDB,
	coinbase *common.Address,
	header *types.Header,
	gp *GasPool,
	chainConfig *params.ChainConfig,
	bc ChainContext,
	cfg vm.Config,
	skipInvalid bool,
	usedGas *uint64,
) ([]*types.Transaction, types.Receipts, []*types.Rip7560TransactionDebugInfo, []*types.Log, error) {
	validatedTransactions := make([]*types.Transaction, 0)
	receipts := make([]*types.Receipt, 0)
	allLogs := make([]*types.Log, 0)

	iTransactions, iReceipts, validationFailureReceipts, iLogs, err := handleRip7560Transactions(
		transactions, index, statedb, coinbase, header, gp, chainConfig, bc, cfg, skipInvalid, usedGas,
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	validatedTransactions = append(validatedTransactions, iTransactions...)
	receipts = append(receipts, iReceipts...)
	allLogs = append(allLogs, iLogs...)
	return validatedTransactions, receipts, validationFailureReceipts, allLogs, nil
}

func handleRip7560Transactions(
	transactions []*types.Transaction,
	index int,
	statedb *state.StateDB,
	coinbase *common.Address,
	header *types.Header,
	gp *GasPool,
	chainConfig *params.ChainConfig,
	bc ChainContext,
	cfg vm.Config,
	skipInvalid bool,
	usedGas *uint64,
) ([]*types.Transaction, types.Receipts, []*types.Rip7560TransactionDebugInfo, []*types.Log, error) {
	validationPhaseResults := make([]*ValidationPhaseResult, 0)
	validatedTransactions := make([]*types.Transaction, 0)
	validationFailureInfos := make([]*types.Rip7560TransactionDebugInfo, 0)
	receipts := make([]*types.Receipt, 0)
	allLogs := make([]*types.Log, 0)
	for i, tx := range transactions[index:] {
		if tx.Type() != types.Rip7560Type {
			break
		}

		statedb.SetTxContext(tx.Hash(), index+i)
		beforeValidationSnapshotId := statedb.Snapshot()
		vpr, vpe := ApplyRip7560ValidationPhases(chainConfig, bc, coinbase, gp, statedb, header, tx, cfg)
		if vpe != nil {
			if skipInvalid {
				log.Error("Validation failed during block building, should not happen, skipping transaction", "error", vpe)
				debugInfo := &types.Rip7560TransactionDebugInfo{
					TxHash:           tx.Hash(),
					RevertData:       vpe.Error(),
					FrameReverted:    false,
					RevertEntityName: "n/a",
				}
				validationFailureInfos = append(validationFailureInfos, debugInfo)
				var vpeCast *ValidationPhaseError
				if errors.As(vpe, &vpeCast) {
					debugInfo.RevertData = vpeCast.reason
					debugInfo.FrameReverted = vpeCast.frameReverted
					debugInfo.RevertEntityName = *vpeCast.revertEntityName
				}
				statedb.RevertToSnapshot(beforeValidationSnapshotId)
				continue
			}
			return nil, nil, nil, nil, vpe
		}
		validationPhaseResults = append(validationPhaseResults, vpr)
		validatedTransactions = append(validatedTransactions, tx)

		// This is the line separating the Validation and Execution phases
		// It should be separated to implement the mempool-friendly AA RIP-7711
		// for i, vpr := range validationPhaseResults

		// TODO: this will miss all validation phase events - pass in 'vpr'
		// statedb.SetTxContext(vpr.Tx.Hash(), i)

		receipt, err := ApplyRip7560ExecutionPhase(chainConfig, vpr, bc, coinbase, gp, statedb, header, cfg, usedGas)

		if err != nil {
			return nil, nil, nil, nil, err
		}
		statedb.Finalise(true)

		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	return validatedTransactions, receipts, validationFailureInfos, allLogs, nil
}

func BuyGasRip7560Transaction(st *types.Rip7560AccountAbstractionTx, state vm.StateDB, gasPrice *uint256.Int) (uint64, *uint256.Int, error) {
	gasLimit, err := st.TotalGasLimit()
	if err != nil {
		return 0, nil, err
	}

	//TODO: check gasLimit against block gasPool
	preCharge := new(uint256.Int).SetUint64(gasLimit)
	preCharge = preCharge.Mul(preCharge, gasPrice)

	chargeFrom := st.GasPayer()

	if have, want := state.GetBalance(*chargeFrom), preCharge; have.Cmp(want) < 0 {
		return 0, nil, fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, chargeFrom.Hex(), have, want)
	}

	state.SubBalance(*chargeFrom, preCharge, 0)
	return gasLimit, preCharge, nil
}

// refund the transaction payer (either account or paymaster) with the excess gas cost
func refundPayer(vpr *ValidationPhaseResult, state vm.StateDB, gasUsed uint64) {
	var chargeFrom = vpr.Tx.Rip7560TransactionData().GasPayer()

	actualGasCost := new(uint256.Int).Mul(vpr.EffectiveGasPrice, new(uint256.Int).SetUint64(gasUsed))

	refund := new(uint256.Int).Sub(vpr.PreCharge, actualGasCost)

	state.AddBalance(*chargeFrom, refund, tracing.BalanceIncreaseGasReturn)
}

// CheckNonceRip7560 checks nonce of RIP-7560 transactions.
// Transactions that don't rely on RIP-7712 two-dimensional nonces are checked statically.
// Transactions using RIP-7712 two-dimensional nonces execute an extra validation frame on-chain.
func CheckNonceRip7560(st *StateTransition, tx *types.Rip7560AccountAbstractionTx) (uint64, error) {
	if tx.IsRip7712Nonce() {
		return performNonceCheckFrameRip7712(st, tx)
	}
	stNonce := st.state.GetNonce(*tx.Sender)
	if msgNonce := tx.Nonce; stNonce < msgNonce {
		return 0, fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh,
			tx.Sender.Hex(), msgNonce, stNonce)
	} else if stNonce > msgNonce {
		return 0, fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooLow,
			tx.Sender.Hex(), msgNonce, stNonce)
	} else if stNonce+1 < stNonce {
		return 0, fmt.Errorf("%w: address %v, nonce: %d", ErrNonceMax,
			tx.Sender.Hex(), stNonce)
	}
	return 0, nil
}

func performNonceCheckFrameRip7712(st *StateTransition, tx *types.Rip7560AccountAbstractionTx) (uint64, error) {
	if !st.evm.ChainConfig().IsRIP7712(st.evm.Context.BlockNumber) {
		return 0, wrapError(fmt.Errorf("RIP-7712 nonce is disabled"))
	}
	nonceManagerMessageData := prepareNonceManagerMessage(tx)
	resultNonceManager := CallFrame(st, &AA_ENTRY_POINT, &AA_NONCE_MANAGER, nonceManagerMessageData, st.gasRemaining)
	if resultNonceManager.Failed() {
		return 0, newValidationPhaseError(
			fmt.Errorf("RIP-7712 nonce validation failed: %w", resultNonceManager.Err),
			resultNonceManager.ReturnData,
			ptr("NonceManager"),
			true,
		)
	}
	return resultNonceManager.UsedGas, nil
}

// call a frame in the context of this state transition.
func CallFrame(st *StateTransition, from *common.Address, to *common.Address, data []byte, gasLimit uint64) *ExecutionResult {
	sender := vm.AccountRef(*from)
	retData, gasRemaining, err := st.evm.Call(sender, *to, data, gasLimit, uint256.NewInt(0))
	usedGas := gasLimit - gasRemaining
	st.gasRemaining -= usedGas

	return &ExecutionResult{
		ReturnData: retData,
		UsedGas:    usedGas,
		Err:        err,
	}
}

func ptr(s string) *string { return &s }

func ApplyRip7560ValidationPhases(
	chainConfig *params.ChainConfig,
	bc ChainContext,
	coinbase *common.Address,
	gp *GasPool,
	statedb *state.StateDB,
	header *types.Header,
	tx *types.Transaction,
	cfg vm.Config,
) (*ValidationPhaseResult, error) {
	aatx := tx.Rip7560TransactionData()
	err := performStaticValidation(aatx, statedb)
	if err != nil {
		return nil, wrapError(err)
	}

	gasPrice := aatx.EffectiveGasPrice(header.BaseFee)
	effectiveGasPrice := uint256.MustFromBig(gasPrice)
	gasLimit, preCharge, err := BuyGasRip7560Transaction(aatx, statedb, effectiveGasPrice)
	if err != nil {
		return nil, wrapError(err)
	}

	blockContext := NewEVMBlockContext(header, bc, coinbase)
	sender := aatx.Sender
	txContext := vm.TxContext{
		Origin:   *aatx.Sender,
		GasPrice: gasPrice,
	}
	evm := vm.NewEVM(blockContext, txContext, statedb, chainConfig, cfg)
	rules := evm.ChainConfig().Rules(evm.Context.BlockNumber, evm.Context.Random != nil, evm.Context.Time)

	statedb.Prepare(rules, *sender, evm.Context.Coinbase, &AA_ENTRY_POINT, vm.ActivePrecompiles(rules), tx.AccessList())

	epc := &EntryPointCall{}

	if evm.Config.Tracer == nil {
		evm.Config.Tracer = &tracing.Hooks{
			OnEnter: epc.OnEnter,
		}
	} else {
		// keep the original tracer's OnEnter hook
		epc.OnEnterSuper = evm.Config.Tracer.OnEnter
		newTracer := *evm.Config.Tracer
		newTracer.OnEnter = epc.OnEnter
		evm.Config.Tracer = &newTracer
	}

	if evm.Config.Tracer.OnTxStart != nil {
		evm.Config.Tracer.OnTxStart(evm.GetVMContext(), tx, common.Address{})
	}

	st := NewStateTransition(evm, nil, gp)
	st.initialGas = gasLimit
	st.gasRemaining = gasLimit

	preTransactionGasCost, err := aatx.PreTransactionGasCost()
	if err != nil {
		return nil, err
	}

	/*** Nonce Manager Frame ***/
	nonceManagerUsedGas, err := CheckNonceRip7560(st, aatx)
	if err != nil {
		return nil, err
	}

	/*** Deployer Frame ***/
	var deploymentUsedGas uint64
	if aatx.Deployer != nil {
		deployerGasLimit := aatx.ValidationGasLimit - preTransactionGasCost
		resultDeployer := CallFrame(st, &AA_SENDER_CREATOR, aatx.Deployer, aatx.DeployerData, deployerGasLimit)
		if resultDeployer.Failed() {
			return nil, newValidationPhaseError(
				resultDeployer.Err,
				resultDeployer.ReturnData,
				ptr("deployer"),
				true,
			)
		}
		if statedb.GetCodeSize(*sender) == 0 {
			return nil, wrapError(
				fmt.Errorf(
					"sender not deployed by the deployer, sender:%s deployer:%s",
					sender.String(), aatx.Deployer.String(),
				))
		}
		deploymentUsedGas = resultDeployer.UsedGas
	} else {
		if !aatx.IsRip7712Nonce() {
			statedb.SetNonce(*sender, statedb.GetNonce(*sender)+1)
		}
	}

	/*** Account Validation Frame ***/
	signer := types.MakeSigner(chainConfig, header.Number, header.Time)
	signingHash := signer.Hash(tx)
	accountValidationMsg, err := prepareAccountValidationMessage(aatx, signingHash)
	if err != nil {
		return nil, wrapError(err)
	}
	accountGasLimit := aatx.ValidationGasLimit - preTransactionGasCost - deploymentUsedGas
	resultAccountValidation := CallFrame(st, &AA_ENTRY_POINT, aatx.Sender, accountValidationMsg, accountGasLimit)
	if resultAccountValidation.Failed() {
		return nil, newValidationPhaseError(
			resultAccountValidation.Err,
			resultAccountValidation.ReturnData,
			ptr("account"),
			true,
		)
	}
	aad, err := validateAccountEntryPointCall(epc, aatx.Sender)
	if err != nil {
		return nil, wrapError(err)
	}

	// clear the EntryPoint calls array after parsing
	epc.err = nil
	epc.Input = nil
	epc.From = common.Address{}

	err = validateValidityTimeRange(header.Time, aad.ValidAfter.Uint64(), aad.ValidUntil.Uint64())
	if err != nil {
		return nil, wrapError(err)
	}

	paymasterContext, pmValidationUsedGas, pmValidAfter, pmValidUntil, err := applyPaymasterValidationFrame(st, epc, tx, signingHash, header)
	if err != nil {
		return nil, err
	}

	gasRefund := st.state.GetRefund()

	vpr := &ValidationPhaseResult{
		Tx:                    tx,
		TxHash:                tx.Hash(),
		PreCharge:             preCharge,
		EffectiveGasPrice:     effectiveGasPrice,
		PaymasterContext:      paymasterContext,
		PreTransactionGasCost: preTransactionGasCost,
		ValidationRefund:      gasRefund,
		DeploymentUsedGas:     deploymentUsedGas,
		NonceManagerUsedGas:   nonceManagerUsedGas,
		ValidationUsedGas:     resultAccountValidation.UsedGas,
		PmValidationUsedGas:   pmValidationUsedGas,
		SenderValidAfter:      aad.ValidAfter.Uint64(),
		SenderValidUntil:      aad.ValidUntil.Uint64(),
		PmValidAfter:          pmValidAfter,
		PmValidUntil:          pmValidUntil,
	}
	statedb.Finalise(true)

	return vpr, nil
}

func performStaticValidation(
	aatx *types.Rip7560AccountAbstractionTx,
	statedb *state.StateDB,
) error {
	hasPaymaster := aatx.Paymaster != nil
	hasPaymasterData := aatx.PaymasterData != nil && len(aatx.PaymasterData) != 0
	hasPaymasterGasLimit := aatx.PaymasterValidationGasLimit != 0
	hasDeployer := aatx.Deployer != nil
	hasDeployerData := aatx.DeployerData != nil && len(aatx.DeployerData) != 0
	hasCodeSender := statedb.GetCodeSize(*aatx.Sender) != 0

	if !hasDeployer && hasDeployerData {
		return wrapError(
			fmt.Errorf(
				"deployer data of size %d is provided but deployer address is not set",
				len(aatx.DeployerData),
			),
		)
	}
	if !hasPaymaster && (hasPaymasterData || hasPaymasterGasLimit) {
		return wrapError(
			fmt.Errorf(
				"paymaster data of size %d (or a gas limit: %d) is provided but paymaster address is not set",
				len(aatx.DeployerData),
				aatx.PaymasterValidationGasLimit,
			),
		)
	}

	if hasPaymaster {
		if !hasPaymasterGasLimit {
			return wrapError(
				fmt.Errorf(
					"paymaster address  %s is provided but 'paymasterVerificationGasLimit' is zero",
					aatx.Paymaster.String(),
				),
			)
		}
		hasCodePaymaster := statedb.GetCodeSize(*aatx.Paymaster) != 0
		if !hasCodePaymaster {
			return wrapError(
				fmt.Errorf(
					"paymaster address %s is provided but contract has no code deployed",
					aatx.Paymaster.String(),
				),
			)
		}
	}

	if hasDeployer {
		hasCodeDeployer := statedb.GetCodeSize(*aatx.Deployer) != 0
		if !hasCodeDeployer {
			return wrapError(
				fmt.Errorf(
					"deployer address %s is provided but contract has no code deployed",
					aatx.Deployer.String(),
				),
			)
		}
		if hasCodeSender {
			return wrapError(
				fmt.Errorf(
					"sender address %s and deployer address %s are provided but sender is already deployed",
					aatx.Sender.String(),
					aatx.Deployer.String(),
				))
		}
	}

	preTransactionGasCost, _ := aatx.PreTransactionGasCost()
	if preTransactionGasCost > aatx.ValidationGasLimit {
		return wrapError(
			fmt.Errorf(
				"insufficient ValidationGasLimit(%d) to cover PreTransactionGasCost(%d)",
				aatx.ValidationGasLimit, preTransactionGasCost,
			),
		)
	}

	if !hasDeployer && !hasCodeSender {
		return wrapError(
			fmt.Errorf(
				"account is not deployed and no deployer is specified, account:%s", aatx.Sender.String(),
			),
		)
	}

	return nil
}

func applyPaymasterValidationFrame(st *StateTransition, epc *EntryPointCall, tx *types.Transaction, signingHash common.Hash, header *types.Header) ([]byte, uint64, uint64, uint64, error) {
	/*** Paymaster Validation Frame ***/
	aatx := tx.Rip7560TransactionData()
	var pmValidationUsedGas uint64
	paymasterMsg, err := preparePaymasterValidationMessage(aatx, signingHash)
	if err != nil {
		return nil, 0, 0, 0, wrapError(err)
	}
	if paymasterMsg == nil {
		return nil, 0, 0, 0, nil
	}
	resultPm := CallFrame(st, &AA_ENTRY_POINT, aatx.Paymaster, paymasterMsg, aatx.PaymasterValidationGasLimit)

	if resultPm.Failed() {
		return nil, 0, 0, 0, newValidationPhaseError(
			resultPm.Err,
			resultPm.ReturnData,
			ptr("paymaster"),
			true,
		)
	}
	pmValidationUsedGas = resultPm.UsedGas
	apd, err := validatePaymasterEntryPointCall(epc, aatx.Paymaster)
	if err != nil {
		return nil, 0, 0, 0, wrapError(err)
	}
	err = validateValidityTimeRange(header.Time, apd.ValidAfter.Uint64(), apd.ValidUntil.Uint64())
	if err != nil {
		return nil, 0, 0, 0, wrapError(err)
	}
	if len(apd.Context) > 0 && aatx.PostOpGas == 0 {
		return nil, 0, 0, 0, wrapError(
			fmt.Errorf(
				"paymaster returned a context of size %d but the paymasterPostOpGasLimit is 0",
				len(apd.Context),
			),
		)
	}
	return apd.Context, pmValidationUsedGas, apd.ValidAfter.Uint64(), apd.ValidUntil.Uint64(), nil
}

func applyPaymasterPostOpFrame(st *StateTransition, aatx *types.Rip7560AccountAbstractionTx, vpr *ValidationPhaseResult, success bool, gasUsed uint64) *ExecutionResult {
	var paymasterPostOpResult *ExecutionResult
	paymasterPostOpMsg := preparePostOpMessage(vpr, success, gasUsed)
	paymasterPostOpResult = CallFrame(st, &AA_ENTRY_POINT, aatx.Paymaster, paymasterPostOpMsg, aatx.PostOpGas)
	return paymasterPostOpResult
}

func capRefund(getRefund uint64, gasUsed uint64) uint64 {
	refund := gasUsed / params.RefundQuotientEIP3529
	if refund > getRefund {
		return getRefund
	}
	return refund
}

func ApplyRip7560ExecutionPhase(
	config *params.ChainConfig,
	vpr *ValidationPhaseResult,
	bc ChainContext,
	author *common.Address,
	gp *GasPool,
	statedb *state.StateDB,
	header *types.Header,
	cfg vm.Config,
	usedGas *uint64,
) (*types.Receipt, error) {

	blockContext := NewEVMBlockContext(header, bc, author)
	aatx := vpr.Tx.Rip7560TransactionData()
	sender := aatx.Sender
	txContext := vm.TxContext{
		Origin:   *sender,
		GasPrice: vpr.EffectiveGasPrice.ToBig(),
	}
	txContext.Origin = *aatx.Sender
	evm := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	st := NewStateTransition(evm, nil, gp)
	st.initialGas = math.MaxUint64
	st.gasRemaining = math.MaxUint64

	accountExecutionMsg := prepareAccountExecutionMessage(vpr.Tx)
	beforeExecSnapshotId := statedb.Snapshot()
	executionResult := CallFrame(st, &AA_ENTRY_POINT, sender, accountExecutionMsg, aatx.Gas)
	receiptStatus := types.ReceiptStatusSuccessful
	executionStatus := ExecutionStatusSuccess
	execRefund := capRefund(st.state.GetRefund(), executionResult.UsedGas)
	if executionResult.Failed() {
		receiptStatus = types.ReceiptStatusFailed
		executionStatus = ExecutionStatusExecutionFailure
	}
	executionGasPenalty := (aatx.Gas - executionResult.UsedGas) * AA_GAS_PENALTY_PCT / 100

	gasUsed := vpr.ValidationUsedGas +
		vpr.NonceManagerUsedGas +
		vpr.DeploymentUsedGas +
		vpr.PmValidationUsedGas +
		vpr.PreTransactionGasCost +
		executionResult.UsedGas +
		executionGasPenalty

	gasRefund := capRefund(execRefund+vpr.ValidationRefund, gasUsed)

	var postOpGasUsed uint64
	var paymasterPostOpResult *ExecutionResult
	if len(vpr.PaymasterContext) != 0 {
		paymasterPostOpResult = applyPaymasterPostOpFrame(st, aatx, vpr, !executionResult.Failed(), gasUsed-gasRefund)
		postOpGasUsed = paymasterPostOpResult.UsedGas
		gasRefund += capRefund(paymasterPostOpResult.RefundedGas, postOpGasUsed)
		// PostOp failed, reverting execution changes
		if paymasterPostOpResult.Failed() {
			statedb.RevertToSnapshot(beforeExecSnapshotId)
			receiptStatus = types.ReceiptStatusFailed
			if executionStatus == ExecutionStatusExecutionFailure {
				executionStatus = ExecutionStatusExecutionAndPostOpFailure
			}
			executionStatus = ExecutionStatusPostOpFailure
		}
		postOpGasPenalty := (aatx.PostOpGas - postOpGasUsed) * AA_GAS_PENALTY_PCT / 100
		postOpGasUsed += postOpGasPenalty
		gasUsed += postOpGasUsed
	}
	gasUsed -= gasRefund
	refundPayer(vpr, statedb, gasUsed)
	payCoinbase(st, aatx, gasUsed)

	err := injectRIP7560TransactionEvent(aatx, executionStatus, header, statedb)
	if err != nil {
		return nil, err
	}
	if aatx.Deployer != nil {
		err = injectRIP7560AccountDeployedEvent(aatx, header, statedb)
		if err != nil {
			return nil, err
		}
	}
	if executionResult.Failed() {
		err = injectRIP7560TransactionRevertReasonEvent(aatx, executionResult.ReturnData, header, statedb)
		if err != nil {
			return nil, err
		}
	}
	if paymasterPostOpResult != nil && paymasterPostOpResult.Failed() {
		err = injectRIP7560TransactionPostOpRevertReasonEvent(aatx, paymasterPostOpResult.ReturnData, header, statedb)
		if err != nil {
			return nil, err
		}
	}

	// TODO: naming convention hell!!! 'usedGas' is 'CumulativeGasUsed' in block processing
	*usedGas += gasUsed

	receipt := &types.Receipt{Type: vpr.Tx.Type(), TxHash: vpr.Tx.Hash(), GasUsed: gasUsed, CumulativeGasUsed: *usedGas}

	receipt.Status = receiptStatus

	// Set the receipt logs and create the bloom filter.
	blockNumber := header.Number
	receipt.Logs = statedb.GetLogs(vpr.TxHash, blockNumber.Uint64(), common.Hash{})
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.TransactionIndex = uint(vpr.TxIndex)
	// other fields are filled in DeriveFields (all tx, block fields, and updating CumulativeGasUsed
	return receipt, nil
}

func injectRIP7560TransactionEvent(
	aatx *types.Rip7560AccountAbstractionTx,
	executionStatus uint64,
	header *types.Header,
	statedb *state.StateDB,
) error {
	topics, data, err := abiEncodeRIP7560TransactionEvent(aatx, executionStatus)
	if err != nil {
		return err
	}
	err = injectEvent(topics, data, header.Number.Uint64(), statedb)
	if err != nil {
		return err
	}
	return nil
}

func injectRIP7560AccountDeployedEvent(
	aatx *types.Rip7560AccountAbstractionTx,
	header *types.Header,
	statedb *state.StateDB,
) error {
	topics, data, err := abiEncodeRIP7560AccountDeployedEvent(aatx)
	if err != nil {
		return err
	}
	err = injectEvent(topics, data, header.Number.Uint64(), statedb)
	if err != nil {
		return err
	}
	return nil
}

func injectRIP7560TransactionRevertReasonEvent(
	aatx *types.Rip7560AccountAbstractionTx,
	revertData []byte,
	header *types.Header,
	statedb *state.StateDB,
) error {
	topics, data, err := abiEncodeRIP7560TransactionRevertReasonEvent(aatx, revertData)
	if err != nil {
		return err
	}
	err = injectEvent(topics, data, header.Number.Uint64(), statedb)
	if err != nil {
		return err
	}
	return nil
}

func injectRIP7560TransactionPostOpRevertReasonEvent(
	aatx *types.Rip7560AccountAbstractionTx,
	revertData []byte,
	header *types.Header,
	statedb *state.StateDB,
) error {
	topics, data, err := abiEncodeRIP7560TransactionPostOpRevertReasonEvent(aatx, revertData)
	if err != nil {
		return err
	}
	err = injectEvent(topics, data, header.Number.Uint64(), statedb)
	if err != nil {
		return err
	}
	return nil
}

func injectEvent(topics []common.Hash, data []byte, blockNumber uint64, statedb *state.StateDB) error {
	transactionLog := &types.Log{
		Address: AA_ENTRY_POINT,
		Topics:  topics,
		Data:    data,
		// This is a non-consensus field, but assigned here because
		// core/state doesn't know the current block number.
		BlockNumber: blockNumber,
	}
	statedb.AddLog(transactionLog)
	return nil
}

// extracted from TransitionDb()
func payCoinbase(st *StateTransition, msg *types.Rip7560AccountAbstractionTx, gasUsed uint64) {
	rules := st.evm.ChainConfig().Rules(st.evm.Context.BlockNumber, st.evm.Context.Random != nil, st.evm.Context.Time)

	effectiveTip := msg.GasTipCap
	if rules.IsLondon {
		effectiveTip = math.BigMin(msg.GasTipCap, new(big.Int).Sub(msg.GasFeeCap, st.evm.Context.BaseFee))
	}

	effectiveTipU256, _ := uint256.FromBig(effectiveTip)

	if st.evm.Config.NoBaseFee && msg.GasFeeCap.Sign() == 0 && msg.GasTipCap.Sign() == 0 {
		// Skip fee payment when NoBaseFee is set and the fee fields
		// are 0. This avoids a negative effectiveTip being applied to
		// the coinbase when simulating calls.
	} else {
		fee := new(uint256.Int).SetUint64(gasUsed)
		fee.Mul(fee, effectiveTipU256)
		st.state.AddBalance(st.evm.Context.Coinbase, fee, tracing.BalanceIncreaseRewardTransactionFee)
		// add the coinbase to the witness iff the fee is greater than 0
		if rules.IsEIP4762 && fee.Sign() != 0 {
			st.evm.AccessEvents.BalanceGas(st.evm.Context.Coinbase, true)
		}
	}
}

func prepareAccountValidationMessage(tx *types.Rip7560AccountAbstractionTx, signingHash common.Hash) ([]byte, error) {
	return abiEncodeValidateTransaction(tx, signingHash)
}

func preparePaymasterValidationMessage(tx *types.Rip7560AccountAbstractionTx, signingHash common.Hash) ([]byte, error) {
	if tx.Paymaster == nil || tx.Paymaster.Cmp(common.Address{}) == 0 {
		return nil, nil
	}
	return abiEncodeValidatePaymasterTransaction(tx, signingHash)
}

func prepareAccountExecutionMessage(baseTx *types.Transaction) []byte {
	tx := baseTx.Rip7560TransactionData()
	return tx.ExecutionData
}

func preparePostOpMessage(vpr *ValidationPhaseResult, success bool, gasUsed uint64) []byte {
	return abiEncodePostPaymasterTransaction(success, gasUsed, vpr.PaymasterContext)
}

func validateAccountEntryPointCall(epc *EntryPointCall, sender *common.Address) (*AcceptAccountData, error) {
	if epc.err != nil {
		return nil, epc.err
	}
	if epc.Input == nil {
		return nil, errors.New("account validation did not call the EntryPoint 'acceptAccount' callback")
	}
	if epc.From.Cmp(*sender) != 0 {
		return nil, errors.New("invalid call to EntryPoint contract from a wrong account address")
	}
	return abiDecodeAcceptAccount(epc.Input, false)
}

func validatePaymasterEntryPointCall(epc *EntryPointCall, paymaster *common.Address) (*AcceptPaymasterData, error) {
	if epc.err != nil {
		return nil, epc.err
	}
	if epc.Input == nil {
		return nil, errors.New("paymaster validation did not call the EntryPoint 'acceptPaymaster' callback")
	}

	if epc.From.Cmp(*paymaster) != 0 {
		return nil, errors.New("invalid call to EntryPoint contract from a wrong paymaster address")
	}
	apd, err := abiDecodeAcceptPaymaster(epc.Input, false)
	if err != nil {
		return nil, err
	}
	return apd, nil
}

func validateValidityTimeRange(time uint64, validAfter uint64, validUntil uint64) error {
	if validUntil == 0 && validAfter == 0 {
		return nil
	}
	if validUntil < validAfter {
		return errors.New("RIP-7560 transaction validity range invalid")
	}
	if time > validUntil {
		return errors.New("RIP-7560 transaction validity expired")
	}
	if time < validAfter {
		return errors.New("RIP-7560 transaction validity not reached yet")
	}
	return nil
}

func (epc *EntryPointCall) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if epc.OnEnterSuper != nil {
		epc.OnEnterSuper(depth, typ, from, to, input, gas, value)
	}
	isRip7560EntryPoint := to.Cmp(AA_ENTRY_POINT) == 0
	if !isRip7560EntryPoint {
		return
	}

	if epc.Input != nil {
		epc.err = errors.New("illegal repeated call to the EntryPoint callback")
		return
	}

	epc.Input = make([]byte, len(input))
	copy(epc.Input, input)
	epc.From = from
}
