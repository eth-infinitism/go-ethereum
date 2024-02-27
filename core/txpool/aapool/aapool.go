package aapool

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"math/big"
	"sync"
	"sync/atomic"
)

type Config struct {
	MaxBundleSize uint
	MaxBundleGas  uint
}

// AccountAbstractionBundlerPool is the transaction pool dedicated to RIP-7560 AA transactions.
// This implementation relies on an external bundler process to perform most of the hard work.
type AccountAbstractionBundlerPool struct {
	config      Config
	chain       legacypool.BlockChain
	txFeed      event.Feed
	currentHead atomic.Pointer[types.Header] // Current head of the blockchain

	pendingBundles  []*types.ExternallyReceivedBundle
	includedBundles map[common.Hash]*types.BundleReceipt

	mu sync.Mutex

	coinbase common.Address
}

func (pool *AccountAbstractionBundlerPool) Init(_ *big.Int, head *types.Header, _ txpool.AddressReserver) error {
	pool.pendingBundles = make([]*types.ExternallyReceivedBundle, 0)
	pool.includedBundles = make(map[common.Hash]*types.BundleReceipt)
	pool.currentHead.Store(head)
	return nil
}

func (pool *AccountAbstractionBundlerPool) Close() error {
	return nil
}

func (pool *AccountAbstractionBundlerPool) Reset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	newIncludedBundles := pool.gatherIncludedBundlesStats(newHead)
	for _, included := range newIncludedBundles {
		pool.includedBundles[included.BundleHash] = included
	}

	pendingBundles := make([]*types.ExternallyReceivedBundle, 0, len(pool.pendingBundles))
	for _, bundle := range pool.pendingBundles {
		nextBlock := big.NewInt(0).Add(newHead.Number, big.NewInt(1))
		if bundle.ValidForBlock.Cmp(nextBlock) == 0 {
			pendingBundles = append(pendingBundles, bundle)
		}
	}
	pool.pendingBundles = pendingBundles
	pool.currentHead.Store(newHead)
}

// For simplicity, this function assumes 'Reset' called for each new block sequentially.
func (pool *AccountAbstractionBundlerPool) gatherIncludedBundlesStats(newHead *types.Header) map[common.Hash]*types.BundleReceipt {
	// 1. Is there a bundle included in the block?

	// note that in 'clique' mode Coinbase is always set to 0x000...000
	if newHead.Coinbase.Cmp(pool.coinbase) != 0 && newHead.Coinbase.Cmp(common.Address{}) != 0 {
		// not our block
		return nil
	}

	// get all transaction hashes in block
	add := pool.chain.GetBlock(newHead.Hash(), newHead.Number.Uint64())
	block := add.Transactions()

	fmt.Printf("gatherIncludedBundlesStats for block %d has transactions count %d", add.Number(), len(add.Transactions()))
	// match transactions in block to bundle ?

	includedBundles := make(map[common.Hash]*types.BundleReceipt)

	// 'pendingBundles' length is expected to be single digits, probably a single bundle in most cases
	for _, bundle := range pool.pendingBundles {
		if len(block) < len(bundle.Transactions) {
			// this bundle does not even fit this block
			continue
		}
		for i := 0; i < len(block); i++ {
			for j := 0; j < len(bundle.Transactions); j++ {
				blockTx := block[i]
				bundleTx := bundle.Transactions[j]
				if bundleTx.Hash().Cmp(blockTx.Hash()) == 0 {
					// tx hash has matched
					if j == len(bundle.Transactions)-1 {
						// FOUND BUNDLE IN BLOCK
						receipt := &types.BundleReceipt{
							BundleHash: bundle.BundleHash,
						}
						includedBundles[bundle.BundleHash] = receipt
					} else {
						// let's see if next tx in bundle matches
						i++
					}
				}
			}
		}

	}
	return includedBundles
}

// SetGasTip is ignored by the External Bundler AA sub pool.
func (pool *AccountAbstractionBundlerPool) SetGasTip(_ *big.Int) {}

func (pool *AccountAbstractionBundlerPool) Has(hash common.Hash) bool {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	tx := pool.Get(hash)
	return tx != nil
}

func (pool *AccountAbstractionBundlerPool) Get(hash common.Hash) *types.Transaction {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	for _, bundle := range pool.pendingBundles {
		for _, tx := range bundle.Transactions {
			if tx.Hash().Cmp(hash) == 0 {
				return tx
			}
		}
	}
	return nil
}

func (pool *AccountAbstractionBundlerPool) Add(_ []*types.Transaction, _ bool, _ bool) []error {
	return nil
}

func (pool *AccountAbstractionBundlerPool) Pending(_ bool) map[common.Address][]*txpool.LazyTransaction {
	return nil
}
func (pool *AccountAbstractionBundlerPool) PendingBundle() (*types.ExternallyReceivedBundle, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	bundle := pool.selectExternalBundle()
	return bundle, nil
}

// SubscribeTransactions is not needed for the External Bundler AA sub pool and 'ch' will never be sent anything.
func (pool *AccountAbstractionBundlerPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, _ bool) event.Subscription {
	return pool.txFeed.Subscribe(ch)
}

// Nonce is only used from 'GetPoolNonce' which is not relevant for AA transactions.
func (pool *AccountAbstractionBundlerPool) Nonce(_ common.Address) uint64 {
	return 0
}

// Stats function not implemented for the External Bundler AA sub pool.
func (pool *AccountAbstractionBundlerPool) Stats() (int, int) {
	return 0, 0
}

// Content function not implemented for the External Bundler AA sub pool.
func (pool *AccountAbstractionBundlerPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return nil, nil
}

// ContentFrom function not implemented for the External Bundler AA sub pool.
func (pool *AccountAbstractionBundlerPool) ContentFrom(_ common.Address) ([]*types.Transaction, []*types.Transaction) {
	return nil, nil
}

// Locals are not necessary for AA Pool
func (pool *AccountAbstractionBundlerPool) Locals() []common.Address {
	return []common.Address{}
}

func (pool *AccountAbstractionBundlerPool) Status(_ common.Hash) txpool.TxStatus {
	panic("implement me")
}

// New creates a new RIP-7560 Account Abstraction Bundler transaction pool.
func New(config Config, chain legacypool.BlockChain, coinbase common.Address) *AccountAbstractionBundlerPool {
	return &AccountAbstractionBundlerPool{
		config:   config,
		chain:    chain,
		coinbase: coinbase,
	}
}

// Filter rejects all individual transactions for External Bundler AA sub pool.
func (pool *AccountAbstractionBundlerPool) Filter(_ *types.Transaction) bool {
	return false
}

func (pool *AccountAbstractionBundlerPool) SubmitBundle(bundle *types.ExternallyReceivedBundle) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	currentBlock := pool.currentHead.Load().Number
	nextBlock := big.NewInt(0).Add(currentBlock, big.NewInt(1))
	log.Error("submitted RIP-7560 bundle valid for block", bundle.ValidForBlock.String(), "next block", nextBlock.String())
	pool.pendingBundles = append(pool.pendingBundles, bundle)
	if nextBlock.Cmp(bundle.ValidForBlock) == 0 {
		pool.txFeed.Send(core.NewTxsEvent{Txs: bundle.Transactions})
	}
	return nil
}

func (pool *AccountAbstractionBundlerPool) GetBundleStatus(hash common.Hash) (*types.BundleReceipt, error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	return pool.includedBundles[hash], nil
}

// Simply returns the bundle with the highest promised revenue by fully trusting the bundler-provided value.
func (pool *AccountAbstractionBundlerPool) selectExternalBundle() *types.ExternallyReceivedBundle {
	var selectedBundle *types.ExternallyReceivedBundle
	for _, bundle := range pool.pendingBundles {
		if selectedBundle == nil || selectedBundle.ExpectedRevenue.Cmp(bundle.ExpectedRevenue) == -1 {
			selectedBundle = bundle
		}
	}
	return selectedBundle
}
