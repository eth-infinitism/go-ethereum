package core

import (
	"encoding/binary"
	"errors"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"math/big"
	"strings"
)

type ValidationPhaseResult struct {
	TxIndex             int
	Tx                  *types.Transaction
	TxHash              common.Hash
	PaymasterContext    []byte
	DeploymentUsedGas   uint64
	ValidationUsedGas   uint64
	PmValidationUsedGas uint64
	SenderValidAfter    uint64
	SenderValidUntil    uint64
	PmValidAfter        uint64
	PmValidUntil        uint64
}

// HandleRip7560Transactions apply state changes of all sequential RIP-7560 transactions and return
// the number of handled transactions
// the transactions array must start with the RIP-7560 transaction
// TODO STOPSHIP: this code has not been checked even once - check manually and provide test coverage
func HandleRip7560Transactions(transactions []*types.Transaction, index int, statedb *state.StateDB, coinbase *common.Address, header *types.Header, gp *GasPool, chainConfig *params.ChainConfig, bc ChainContext, cfg vm.Config) ([]*types.Transaction, types.Receipts, []*types.Log, error) {
	validatedTransactions := make([]*types.Transaction, 0)
	receipts := make([]*types.Receipt, 0)
	allLogs := make([]*types.Log, 0)

	i := index
	for {
		if i >= len(transactions) {
			break
		}
		batchEnd := len(transactions) - 1
		if transactions[i].Type() != types.Rip7560Type {
			break
		}
		subtype := transactions[i].Rip7560TransactionSubtype()
		if subtype == types.HeaderCounterSubtype {
			header := transactions[i].Rip7560HeaderTxData()
			// "jump" to the next expected header on next iteration
			i += int(header.TransactionsCount)
			batchEnd = i
			// todo: check batch size is valid (fits, >0, etc.)
		} else {
			// "jump" outside the array on next iteration
			i = len(transactions)
		}
		iTransactions, iReceipts, iLogs, err := handleRip7560Transactions(transactions[:batchEnd], index, statedb, coinbase, header, gp, chainConfig, bc, cfg)
		if err != nil {
			return nil, nil, nil, err
		}
		validatedTransactions = append(validatedTransactions, iTransactions...)
		receipts = append(receipts, iReceipts...)
		allLogs = append(allLogs, iLogs...)
	}
	return validatedTransactions, receipts, allLogs, nil
}

func handleRip7560Transactions(transactions []*types.Transaction, index int, statedb *state.StateDB, coinbase *common.Address, header *types.Header, gp *GasPool, chainConfig *params.ChainConfig, bc ChainContext, cfg vm.Config) ([]*types.Transaction, types.Receipts, []*types.Log, error) {
	validationPhaseResults := make([]*ValidationPhaseResult, 0)
	validatedTransactions := make([]*types.Transaction, 0)
	receipts := make([]*types.Receipt, 0)
	allLogs := make([]*types.Log, 0)
	for i, tx := range transactions[index:] {
		if tx.Type() == types.Rip7560Type {
			statedb.SetTxContext(tx.Hash(), index+i)
			err := BuyGasAATransaction(tx.Rip7560TransactionData(), statedb)
			if err != nil {
				return nil, nil, nil, err
			}
			vpr, err := ApplyRip7560ValidationPhases(chainConfig, bc, coinbase, gp, statedb, header, tx, cfg)
			if err != nil {
				return nil, nil, nil, err
			}
			validationPhaseResults = append(validationPhaseResults, vpr)
			validatedTransactions = append(validatedTransactions, tx)
		} else {
			break
		}
	}
	for i, vpr := range validationPhaseResults {

		// TODO: this will miss all validation phase events - pass in 'vpr'
		statedb.SetTxContext(vpr.Tx.Hash(), i)

		receipt, err := ApplyRip7560ExecutionPhase(chainConfig, vpr, bc, coinbase, gp, statedb, header, cfg)

		if err != nil {
			return nil, nil, nil, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	return validatedTransactions, receipts, allLogs, nil
}

// GetRip7560AccountNonce reads the two-dimensional RIP-7560 nonce from the given blockchain state
func GetRip7560AccountNonce(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, cfg vm.Config, sender common.Address, nonceKey *big.Int) uint64 {

	// todo: this is a copy paste of 5 lines that need 8 parameters to run, wtf?
	blockContext := NewEVMBlockContext(header, bc, author)
	message, err := TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	txContext := NewEVMTxContext(message)
	vmenv := vm.NewEVM(blockContext, txContext, statedb, config, cfg)
	vmenv.Reset(txContext, statedb) // TODO what does this 'reset' do?

	from := common.HexToAddress("0x0000000000000000000000000000000000000000")
	// todo: read NM address from global config
	nonceManager := common.HexToAddress("0xdebc121d1b09bc03ff57fa1f96514d04a1f0f59d")
	fromBigNonceKey256, _ := uint256.FromBig(nonceKey)
	key := make([]byte, 24)
	fromBigNonceKey256.WriteToSlice(key)
	nonceManagerData := make([]byte, 0)
	nonceManagerData = append(nonceManagerData[:], sender.Bytes()...)
	nonceManagerData = append(nonceManagerData[:], key...)

	nonceManagerMsg := &Message{
		From:              from,
		To:                &nonceManager,
		Value:             big.NewInt(0),
		GasLimit:          100000,
		GasPrice:          big.NewInt(875000000),
		GasFeeCap:         big.NewInt(875000000),
		GasTipCap:         big.NewInt(875000000),
		Data:              nonceManagerData,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsInnerAATxFrame:  true,
	}
	resultNonceManager, err := ApplyAATxMessage(vmenv, nonceManagerMsg, gp)
	if err != nil {
		// todo: handle
		return 777
	}
	if resultNonceManager.Err != nil {
		return 888
	}
	if resultNonceManager.ReturnData == nil {
		return 999
	}
	return big.NewInt(0).SetBytes(resultNonceManager.ReturnData).Uint64()
}

func ApplyRip7560ValidationPhases(chainConfig *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, cfg vm.Config) (*ValidationPhaseResult, error) {
	/*** Nonce Manger Frame ***/
	nonceManagerMsg := prepareNonceManagerMessage(tx, chainConfig)

	blockContext := NewEVMBlockContext(header, bc, author)
	txContext := NewEVMTxContext(nonceManagerMsg)
	evm := vm.NewEVM(blockContext, txContext, statedb, chainConfig, cfg)

	resultNonceManager, err := ApplyAATxMessage(evm, nonceManagerMsg, gp)
	if err != nil {
		return nil, err
	}
	statedb.IntermediateRoot(true)
	if resultNonceManager.Err != nil {
		return nil, resultNonceManager.Err
	}

	/*** Deployer Frame ***/
	deployerMsg := prepareDeployerMessage(tx, chainConfig)
	var deploymentUsedGas uint64
	if deployerMsg != nil {
		resultDeployer, err := ApplyAATxMessage(evm, deployerMsg, gp)
		if err != nil {
			return nil, err
		}
		statedb.IntermediateRoot(true)
		if resultDeployer.Failed() {
			// TODO: bubble up the inner error message to the user, if possible
			return nil, errors.New("account deployment  failed - invalid transaction")
		}
		deploymentUsedGas = resultDeployer.UsedGas
	}

	/*** Account Validation Frame ***/
	signer := types.MakeSigner(chainConfig, header.Number, header.Time)
	signingHash := signer.Hash(tx)
	accountValidationMsg, err := prepareAccountValidationMessage(tx, chainConfig, signingHash, deploymentUsedGas)
	resultAccountValidation, err := ApplyAATxMessage(evm, accountValidationMsg, gp)
	if err != nil {
		return nil, err
	}
	statedb.IntermediateRoot(true)
	if resultAccountValidation.Err != nil {
		return nil, resultAccountValidation.Err
	}
	validAfter, validUntil, err := validateAccountReturnData(resultAccountValidation.ReturnData)
	if err != nil {
		return nil, err
	}
	err = validateValidityTimeRange(header.Time, validAfter, validUntil)
	if err != nil {
		return nil, err
	}

	/*** Paymaster Validation Frame ***/
	var pmValidationUsedGas uint64
	var paymasterContext []byte
	var pmValidAfter uint64
	var pmValidUntil uint64
	paymasterMsg, err := preparePaymasterValidationMessage(tx, chainConfig, signingHash)
	if paymasterMsg != nil {
		resultPm, err := ApplyAATxMessage(evm, paymasterMsg, gp)
		if err != nil {
			return nil, err
		}
		statedb.IntermediateRoot(true)
		if resultPm.Failed() {
			return nil, errors.New("paymaster validation failed - invalid transaction")
		}
		pmValidationUsedGas = resultPm.UsedGas
		paymasterContext, pmValidAfter, pmValidUntil, err = validatePaymasterReturnData(resultPm.ReturnData)
		if err != nil {
			return nil, err
		}
		err = validateValidityTimeRange(header.Time, pmValidAfter, pmValidUntil)
		if err != nil {
			return nil, err
		}
	}

	vpr := &ValidationPhaseResult{
		Tx:                  tx,
		TxHash:              tx.Hash(),
		PaymasterContext:    paymasterContext,
		DeploymentUsedGas:   deploymentUsedGas,
		ValidationUsedGas:   resultAccountValidation.UsedGas,
		PmValidationUsedGas: pmValidationUsedGas,
		SenderValidAfter:    validAfter,
		SenderValidUntil:    validUntil,
		PmValidAfter:        pmValidAfter,
		PmValidUntil:        pmValidUntil,
	}

	return vpr, nil
}

func ApplyRip7560ExecutionPhase(config *params.ChainConfig, vpr *ValidationPhaseResult, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, cfg vm.Config) (*types.Receipt, error) {

	// TODO: snapshot EVM - we will revert back here if postOp fails

	blockContext := NewEVMBlockContext(header, bc, author)
	message, err := TransactionToMessage(vpr.Tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	txContext := NewEVMTxContext(message)
	evm := vm.NewEVM(blockContext, txContext, statedb, config, cfg)

	accountExecutionMsg := prepareAccountExecutionMessage(vpr.Tx, evm.ChainConfig())
	executionResult, err := ApplyAATxMessage(evm, accountExecutionMsg, gp)
	if err != nil {
		return nil, err
	}
	root := statedb.IntermediateRoot(true).Bytes()
	var paymasterPostOpResult *ExecutionResult
	if len(vpr.PaymasterContext) != 0 {
		paymasterPostOpMsg, err := preparePostOpMessage(vpr, evm.ChainConfig(), executionResult)
		if err != nil {
			return nil, err
		}
		paymasterPostOpResult, err = ApplyAATxMessage(evm, paymasterPostOpMsg, gp)
		if err != nil {
			return nil, err
		}
		// TODO: revert the execution phase changes
		root = statedb.IntermediateRoot(true).Bytes()
	}

	cumulativeGasUsed :=
		vpr.ValidationUsedGas +
			vpr.DeploymentUsedGas +
			vpr.PmValidationUsedGas +
			executionResult.UsedGas
	if paymasterPostOpResult != nil {
		cumulativeGasUsed +=
			paymasterPostOpResult.UsedGas
	}

	receipt := &types.Receipt{Type: vpr.Tx.Type(), PostState: root, CumulativeGasUsed: cumulativeGasUsed}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(vpr.Tx.Hash(), header.Number.Uint64(), header.Hash())

	if executionResult.Failed() || (paymasterPostOpResult != nil && paymasterPostOpResult.Failed()) {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	return receipt, err
}

func prepareNonceManagerMessage(baseTx *types.Transaction, chainConfig *params.ChainConfig) *Message {
	tx := baseTx.Rip7560TransactionData()
	key := make([]byte, 32)
	fromBig, _ := uint256.FromBig(tx.BigNonce)
	fromBig.WriteToSlice(key)

	nonceManagerData := make([]byte, 0)
	nonceManagerData = append(nonceManagerData[:], tx.Sender.Bytes()...)
	nonceManagerData = append(nonceManagerData[:], key...)
	return &Message{
		From:              chainConfig.EntryPointAddress,
		To:                &chainConfig.NonceManagerAddress,
		Value:             big.NewInt(0),
		GasLimit:          100000,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              nonceManagerData,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsInnerAATxFrame:  true,
	}
}

func prepareDeployerMessage(baseTx *types.Transaction, config *params.ChainConfig) *Message {
	tx := baseTx.Rip7560TransactionData()
	if len(tx.DeployerData) < 20 {
		return nil
	}
	var deployerAddress common.Address = [20]byte(tx.DeployerData[0:20])
	return &Message{
		From:              config.DeployerCallerAddress,
		To:                &deployerAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              tx.DeployerData[20:],
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsInnerAATxFrame:  true,
	}
}

func prepareAccountValidationMessage(baseTx *types.Transaction, chainConfig *params.ChainConfig, signingHash common.Hash, deploymentUsedGas uint64) (*Message, error) {
	tx := baseTx.Rip7560TransactionData()
	jsondata := `[
	{"type":"function","name":"validateTransaction","inputs": [{"name": "version","type": "uint256"},{"name": "txHash","type": "bytes32"},{"name": "transaction","type": "bytes"}]}
	]`

	validateTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		return nil, err
	}
	txAbiEncoding, err := tx.AbiEncode()
	validateTransactionData, err := validateTransactionAbi.Pack("validateTransaction", big.NewInt(0), signingHash, txAbiEncoding)
	return &Message{
		From:              chainConfig.EntryPointAddress,
		To:                tx.Sender,
		Value:             big.NewInt(0),
		GasLimit:          tx.ValidationGas - deploymentUsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              validateTransactionData,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsInnerAATxFrame:  true,
	}, nil
}

func preparePaymasterValidationMessage(baseTx *types.Transaction, config *params.ChainConfig, signingHash common.Hash) (*Message, error) {
	tx := baseTx.Rip7560TransactionData()
	if len(tx.PaymasterData) < 20 {
		return nil, nil
	}
	var paymasterAddress common.Address = [20]byte(tx.PaymasterData[0:20])
	jsondata := `[
	{"type":"function","name":"validatePaymasterTransaction","inputs": [{"name": "version","type": "uint256"},{"name": "txHash","type": "bytes32"},{"name": "transaction","type": "bytes"}]}
	]`

	validateTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	txAbiEncoding, err := tx.AbiEncode()
	data, err := validateTransactionAbi.Pack("validatePaymasterTransaction", big.NewInt(0), signingHash, txAbiEncoding)

	if err != nil {
		return nil, err
	}
	return &Message{
		From:              config.EntryPointAddress,
		To:                &paymasterAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.PaymasterGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              data,
		AccessList:        make(types.AccessList, 0),
		SkipAccountChecks: true,
		IsInnerAATxFrame:  true,
	}, nil
}

func prepareAccountExecutionMessage(baseTx *types.Transaction, config *params.ChainConfig) *Message {
	tx := baseTx.Rip7560TransactionData()
	return &Message{
		From:              config.EntryPointAddress,
		To:                tx.Sender,
		Value:             big.NewInt(0),
		GasLimit:          tx.Gas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              tx.Data,
		AccessList:        tx.AccessList,
		SkipAccountChecks: true,
		IsInnerAATxFrame:  true,
	}
}

func preparePostOpMessage(vpr *ValidationPhaseResult, chainConfig *params.ChainConfig, executionResult *ExecutionResult) (*Message, error) {
	if len(vpr.PaymasterContext) == 0 {
		return nil, nil
	}

	tx := vpr.Tx.Rip7560TransactionData()
	jsondata := `[
			{"type":"function","name":"postPaymasterTransaction","inputs": [{"name": "success","type": "bool"},{"name": "actualGasCost","type": "uint256"},{"name": "context","type": "bytes"}]}
		]`
	postPaymasterTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		return nil, err
	}
	postOpData, err := postPaymasterTransactionAbi.Pack("postPaymasterTransaction", true, big.NewInt(0), vpr.PaymasterContext)
	if err != nil {
		return nil, err
	}
	var paymasterAddress common.Address = [20]byte(tx.PaymasterData[0:20])
	return &Message{
		From:              chainConfig.EntryPointAddress,
		To:                &paymasterAddress,
		Value:             big.NewInt(0),
		GasLimit:          tx.PaymasterGas - executionResult.UsedGas,
		GasPrice:          tx.GasFeeCap,
		GasFeeCap:         tx.GasFeeCap,
		GasTipCap:         tx.GasTipCap,
		Data:              postOpData,
		AccessList:        tx.AccessList,
		SkipAccountChecks: true,
		IsInnerAATxFrame:  true,
	}, nil
}

func validateAccountReturnData(data []byte) (uint64, uint64, error) {
	MAGIC_VALUE_SENDER := uint32(0xbf45c166)
	if len(data) != 32 {
		return 0, 0, errors.New("invalid account return data length")
	}
	magicExpected := binary.BigEndian.Uint32(data[:4])
	if magicExpected != MAGIC_VALUE_SENDER {
		return 0, 0, errors.New("account did not return correct MAGIC_VALUE")
	}
	validAfter := binary.BigEndian.Uint64(data[4:12])
	validUntil := binary.BigEndian.Uint64(data[12:20])
	return validAfter, validUntil, nil
}

func validatePaymasterReturnData(data []byte) ([]byte, uint64, uint64, error) {
	MAGIC_VALUE_PAYMASTER := uint32(0xe0e6183a)
	if len(data) < 4 {
		return nil, 0, 0, errors.New("invalid paymaster return data length")
	}
	magicExpected := binary.BigEndian.Uint32(data[:4])
	if magicExpected != MAGIC_VALUE_PAYMASTER {
		return nil, 0, 0, errors.New("paymaster did not return correct MAGIC_VALUE")
	}

	jsondata := `[
			{"type":"function","name":"validatePaymasterTransaction","outputs": [{"name": "context","type": "bytes"},{"name": "validUntil","type": "uint256"},{"name": "validAfter","type": "uint256"}]}
		]`
	validatePaymasterTransactionAbi, err := abi.JSON(strings.NewReader(jsondata))
	if err != nil {
		// todo: wrap error message
		return nil, 0, 0, err
	}
	decodedPmReturnData, err := validatePaymasterTransactionAbi.Unpack("validatePaymasterTransaction", data[4:])
	if err != nil {
		return nil, 0, 0, err
	}
	context := decodedPmReturnData[0].([]byte)
	validAfter := decodedPmReturnData[1].(*big.Int)
	validUntil := decodedPmReturnData[2].(*big.Int)
	return context, validAfter.Uint64(), validUntil.Uint64(), nil
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
