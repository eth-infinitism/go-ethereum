package aapool

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/blobpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"sync"
	"sync/atomic"
)

type Config struct {
	// nonce manager address
	// ops per staked/unstaked ACC/PM/DEPL
	// max validation gas limit
}

// Reputations are maintained per entity as defined in ERC-7562
type Reputations struct {
	// opsSeen, opsIncluded
}

// AlexfAccountAbstractionPool is the transaction pool dedicated to RIP-7560 AA transactions.
type AlexfAccountAbstractionPool struct {
	discoverFeed event.Feed // Event feed to send out new tx events on pool inclusion (reorg included)
	//storedTransaction *types.Transaction
	pending       map[common.Address][]*types.Transaction
	pendingByHash map[common.Hash]*types.Transaction

	incoming map[common.Hash][]*types.Transaction // transactions that were not validated yet

	externalBundles []*txpool.ExternallyReceivedBundle

	nonces *BigNoncer

	// stuff needed to run the tracer on validation code
	chainConfig *params.ChainConfig
	// todo: chain is a god object and certainly should not be passed to a mempool, right?
	chain       *core.BlockChain
	currentHead atomic.Pointer[types.Header] // Current head of the blockchain

	// todo: proper thread safety
	mu sync.Mutex
}

// loop is the transaction pool's main event loop, waiting for and reacting to
// outside blockchain events as well as for various reporting and transaction
// eviction events.
func (pool *AlexfAccountAbstractionPool) loop() {
	var promoteAddrs []common.Address
	pool.promoteExecutables(promoteAddrs)

	pool.demoteUnexecutables()
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
func (pool *AlexfAccountAbstractionPool) promoteExecutables(accounts []common.Address) []*types.Transaction {
	return nil
}

// promoteTx adds a transaction to the pending (processable) list of transactions
// and returns whether it was inserted or an older was better.
func (pool *AlexfAccountAbstractionPool) promoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) bool {
	return true
}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
func (pool *AlexfAccountAbstractionPool) demoteUnexecutables() {
	// start copy-paste "nonce getter" code for bundles
	for _, bundle := range pool.externalBundles {
		tx := bundle.Transactions[0]
		sender := *tx.AlexfAATransactionData().Sender
		// todo: rewrite
		aatx := tx.AlexfAATransactionData()
		nonceKey := new(big.Int)
		nonceKey.Set(aatx.BigNonce)
		nonceKey = nonceKey.Rsh(nonceKey, 64)
		nonceValue := aatx.BigNonce.Uint64()
		header := pool.currentHead.Load()
		gaspool := new(core.GasPool)
		statedb, _ := pool.chain.State()
		currentValue := core.GetNonce(
			pool.chainConfig, pool.chain, &header.Coinbase, gaspool, statedb, header, tx, *pool.chain.GetVMConfig(),
			sender, nonceKey)
		if nonceValue < currentValue {
			fmt.Printf("\nALEXF: !! Dropping a bundle !!")
			pool.externalBundles = make([]*txpool.ExternallyReceivedBundle, 0)
		}
	}
	// end copy-paste "nonce getter" code for bundles

	for sender, transactions := range pool.pending {
		for index, tx := range transactions {
			// todo: rewrite
			aatx := tx.AlexfAATransactionData()
			nonceKey := new(big.Int)
			nonceKey.Set(aatx.BigNonce)
			nonceKey = nonceKey.Rsh(nonceKey, 64)
			nonceValue := aatx.BigNonce.Uint64()
			header := pool.currentHead.Load()
			gaspool := new(core.GasPool)
			statedb, _ := pool.chain.State()
			currentValue := core.GetNonce(
				pool.chainConfig, pool.chain, &header.Coinbase, gaspool, statedb, header, tx, *pool.chain.GetVMConfig(),
				sender, nonceKey)
			if nonceValue < currentValue {
				fmt.Printf("\nALEXF: !! Removing AA transaction from mempool nonceValue: %d currentValue: %d\n  %s", nonceValue, currentValue, tx.Hash())
				pool.pending[sender] = append(pool.pending[sender][:index], pool.pending[sender][index+1:]...)
			}
		}
		if len(pool.pending[sender]) == 0 {
			fmt.Printf("\nALEXF: !! Removing AA sender: %s", sender)
			delete(pool.pending, sender)
		}
	}
}

func (pool *AlexfAccountAbstractionPool) Init(gasTip *big.Int, head *types.Header, reserve txpool.AddressReserver) error {
	pool.nonces = &BigNoncer{
		noncePerSenderPerKey: make(map[common.Address]map[string]uint64),
	}
	pool.pending = make(map[common.Address][]*types.Transaction)
	pool.pendingByHash = make(map[common.Hash]*types.Transaction)
	pool.externalBundles = make([]*txpool.ExternallyReceivedBundle, 0)
	pool.currentHead.Store(head)
	//TODO implement me
	//panic("implement me")
	return nil
}

func (pool *AlexfAccountAbstractionPool) Close() error {
	//TODO implement me
	//panic("implement me")
	return nil
}

func (pool *AlexfAccountAbstractionPool) Reset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	// just synchronously running a 'loop' for now
	fmt.Printf("\nALEXF: AAPool Reset %s %s", oldHead.Number.String(), newHead.Number.String())
	pool.currentHead.Store(newHead)
	pool.loop()
	//TODO implement me
	//panic("implement me")
	return
}

func (pool *AlexfAccountAbstractionPool) SetGasTip(tip *big.Int) {
	//TODO implement me
	//panic("implement me")
}

func (pool *AlexfAccountAbstractionPool) Has(hash common.Hash) bool {
	//TODO implement me
	panic("implement me")
}

func (pool *AlexfAccountAbstractionPool) Get(hash common.Hash) *types.Transaction {
	tx := pool.get(hash)
	if tx == nil {
		return nil
	}
	return tx
}

func (pool *AlexfAccountAbstractionPool) validateTransaction(tx *types.Transaction) error {
	header := pool.currentHead.Load()
	gaspool := new(core.GasPool)
	statedb, err := pool.chain.State()
	if err != nil {
		return err
	}
	// TODO: just overriding the tracer here is probably not the best idea
	origTracer := pool.chain.GetVMConfig().Tracer
	//pool.chain.GetVMConfig().Tracer = new(ValidationRulesTracer)
	if err != nil {
		return err
	}

	stateDbCopy := statedb.Copy()
	_, err = core.ApplyAlexfAATransactionValidationPhase(pool.chainConfig, pool.chain, &header.Coinbase, gaspool, stateDbCopy, header, tx, *pool.chain.GetVMConfig())
	pool.chain.GetVMConfig().Tracer = origTracer
	pool.chain.GetVMConfig().NoBaseFee = false
	if err != nil {
		return err
	}
	return nil
}

func (pool *AlexfAccountAbstractionPool) Add(txs []*types.Transaction, local bool, sync bool) []error {
	if len(txs) > 0 {
		fmt.Printf("\nALEXF: AAPool Add %d\n", len(txs))
	}
	var (
		adds = make([]*types.Transaction, 0, len(txs))
		errs = make([]error, len(txs))
	)
	for i, tx := range txs {
		errs[i] = pool.add(tx)
		if errs[i] == nil {
			adds = append(adds, tx.WithoutBlobTxSidecar())
		}
	}
	if len(adds) > 0 {
		pool.discoverFeed.Send(core.NewTxsEvent{Txs: adds})
		//p.insertFeed.Send(core.NewTxsEvent{Txs: adds})
	}
	return errs
}

//goland:noinspection GoUnreachableCode
func (pool *AlexfAccountAbstractionPool) add(tx *types.Transaction) error {
	if tx.Type() != types.ALEXF_AA_TX_TYPE {
		return nil
	}
	// todo: implement full transaction tracing and validation to enable adding txs from mempool
	panic("adding individual Type 4 transactions is disabled")
	//fmt.Printf("\nALEXF: Adding AA transaction to mempool %s %d\n", tx.Hash(), tx.Nonce())
	err := pool.validateTransaction(tx)
	if err != nil {
		return err
	}
	sender := *tx.AlexfAATransactionData().Sender
	pool.pending[sender] = append(pool.pending[sender], tx)
	pool.pendingByHash[tx.Hash()] = tx
	return nil
}

func (pool *AlexfAccountAbstractionPool) Pending(enforceTips bool) map[common.Address][]*txpool.LazyTransaction {

	pool.mu.Lock()
	defer pool.mu.Unlock()

	pending := make(map[common.Address][]*txpool.LazyTransaction)

	selectedBundle := pool.selectExternalBundle()

	if selectedBundle != nil {
		for _, tx := range selectedBundle.Transactions {
			// TODO: strongly assuming one tx per sender in bundler here...
			sender := tx.AlexfAATransactionData().Sender
			lts := make([]*txpool.LazyTransaction, 1)
			lts[0] = &txpool.LazyTransaction{
				Pool:      pool,
				Hash:      tx.Hash(),
				Tx:        tx,
				Time:      tx.Time(),
				GasFeeCap: tx.GasFeeCap(),
				GasTipCap: tx.GasTipCap(),
				Gas:       tx.Gas(),
				BlobGas:   tx.BlobGas(),
			}
			pending[*sender] = lts
		}
	} else {
		for sender, txs := range pool.pending {
			lts := make([]*txpool.LazyTransaction, len(txs))
			for i, tx := range txs {
				lts[i] = &txpool.LazyTransaction{
					Pool:      pool,
					Hash:      tx.Hash(),
					Tx:        tx,
					Time:      tx.Time(),
					GasFeeCap: tx.GasFeeCap(),
					GasTipCap: tx.GasTipCap(),
					Gas:       tx.Gas(),
					BlobGas:   tx.BlobGas(),
				}
			}
			pending[sender] = lts
		}
	}
	fmt.Printf("\nALEXF: AAPool Pending len= %d\n", len(pending))
	return pending
}

func (pool *AlexfAccountAbstractionPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	//TODO implement me
	return pool.discoverFeed.Subscribe(ch)
}

// Nonce is only used from 'GetPoolNonce' which is not relevant for AA transactions
func (pool *AlexfAccountAbstractionPool) Nonce(addr common.Address) uint64 {
	return 0
}

func (pool *AlexfAccountAbstractionPool) Stats() (int, int) {
	//TODO implement me
	panic("implement me")
}

func (pool *AlexfAccountAbstractionPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	//TODO implement me
	panic("implement me")
}

func (pool *AlexfAccountAbstractionPool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	//TODO implement me
	panic("implement me")
}

// Locals are not necessary for AA Pool
func (pool *AlexfAccountAbstractionPool) Locals() []common.Address {
	return []common.Address{}
}

func (pool *AlexfAccountAbstractionPool) Status(hash common.Hash) txpool.TxStatus {
	//TODO implement me
	panic("implement me")
}

// New creates a new blob transaction pool to gather, sort and filter inbound
// blob transactions from the network.
func New(config blobpool.Config, chain *core.BlockChain, chainConfig *params.ChainConfig) *AlexfAccountAbstractionPool {
	// Sanitize the input to ensure no vulnerable gas prices are set
	//config = (&config).sanitize()

	// Create the transaction pool with its initial settings
	return &AlexfAccountAbstractionPool{
		//config: config,
		//signer: types.LatestSigner(chain.Config()),
		chain:       chain,
		chainConfig: chainConfig,
		//lookup: make(map[common.Hash]uint64),
		//index:  make(map[common.Address][]*blobTxMeta),
		//spent:  make(map[common.Address]*uint256.Int),
	}
}

// Filter returns whether the given transaction can be consumed by the pool.
func (pool *AlexfAccountAbstractionPool) Filter(tx *types.Transaction) bool {
	return tx.Type() == types.ALEXF_AA_TX_TYPE
}

// get returns a transaction if it is contained in the pool and nil otherwise.
func (pool *AlexfAccountAbstractionPool) get(hash common.Hash) *types.Transaction {
	return pool.pendingByHash[hash]
}

func (pool *AlexfAccountAbstractionPool) SubmitBundle(bundle *txpool.ExternallyReceivedBundle) {
	pool.externalBundles = append(pool.externalBundles, bundle)
}

func (pool *AlexfAccountAbstractionPool) selectExternalBundle() *txpool.ExternallyReceivedBundle {
	if len(pool.externalBundles) > 0 {
		// TODO: how (and when?) do I remove a "selected" bundle?
		return pool.externalBundles[0]
	}
	return nil
}
