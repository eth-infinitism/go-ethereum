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

// AccountAbstractionPool is the transaction pool dedicated to RIP-7560 AA transactions.
type AlexfAccountAbstractionPool struct {
	discoverFeed event.Feed // Event feed to send out new tx events on pool inclusion (reorg included)
	//storedTransaction *types.Transaction
	pending       map[common.Address][]*types.Transaction
	pendingByHash map[common.Hash]*types.Transaction

	// stuff needed to run the tracer on validation code
	chainConfig *params.ChainConfig
	// todo: chain is a god object and certainly should not be passed to a mempool, right?
	chain       *core.BlockChain
	currentHead atomic.Pointer[types.Header] // Current head of the blockchain
}

func (pool *AlexfAccountAbstractionPool) Init(gasTip *big.Int, head *types.Header, reserve txpool.AddressReserver) error {
	pool.pending = make(map[common.Address][]*types.Transaction)
	pool.pendingByHash = make(map[common.Hash]*types.Transaction)
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
	//TODO implement me
	//panic("implement me")
	return
}

func (pool *AlexfAccountAbstractionPool) SetGasTip(tip *big.Int) {
	//TODO implement me
	panic("implement me")
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
	pool.chain.GetVMConfig().Tracer = new(ValidationRulesTracer)
	if err != nil {
		return err
	}
	header.BaseFee = big.NewInt(1) // todo: fix
	_, err = core.ApplyAlexfAATransactionValidationPhase(pool.chainConfig, pool.chain, &header.Coinbase, gaspool, statedb, header, tx, *pool.chain.GetVMConfig())
	pool.chain.GetVMConfig().Tracer = origTracer
	pool.chain.GetVMConfig().NoBaseFee = false
	if err != nil {
		return err
	}
	return nil
}

func (pool *AlexfAccountAbstractionPool) Add(txs []*types.Transaction, local bool, sync bool) []error {
	var (
		adds = make([]*types.Transaction, 0, len(txs))
		errs = make([]error, len(txs))
	)
	for i, tx := range txs {
		pool.validateTransaction(tx)
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

// TODO: perform validation frame when adding a transaction to the AA mempool
func (pool *AlexfAccountAbstractionPool) add(tx *types.Transaction) (err error) {
	if tx.Type() == types.ALEXF_AA_TX_TYPE {
		fmt.Printf("\nALEXF: Adding AA transaction to mempool %s %d\n", tx.Hash(), tx.Nonce())
		sender := *tx.AlexfAATransactionData().Sender
		pool.pending[sender] = append(pool.pending[sender], tx)
		pool.pendingByHash[tx.Hash()] = tx
	}
	return nil
}

func (pool *AlexfAccountAbstractionPool) Pending(enforceTips bool) map[common.Address][]*txpool.LazyTransaction {
	//TODO implement me
	pending := make(map[common.Address][]*txpool.LazyTransaction)
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
	fmt.Printf("\nALEXF: Returning pending AA transaction to mempool, len= %d\n", len(pending))
	return pending
}

func (pool *AlexfAccountAbstractionPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	//TODO implement me
	return pool.discoverFeed.Subscribe(ch)
}

func (pool *AlexfAccountAbstractionPool) Nonce(addr common.Address) uint64 {
	//TODO implement me
	//panic("implement me")
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

func (pool *AlexfAccountAbstractionPool) Locals() []common.Address {
	//TODO implement me
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

// Filter returns whether the given transaction can be consumed by the blob pool.
func (pool *AlexfAccountAbstractionPool) Filter(tx *types.Transaction) bool {
	return tx.Type() == types.ALEXF_AA_TX_TYPE
}

// get returns a transaction if it is contained in the pool and nil otherwise.
func (pool *AlexfAccountAbstractionPool) get(hash common.Hash) *types.Transaction {
	return pool.pendingByHash[hash]
}
