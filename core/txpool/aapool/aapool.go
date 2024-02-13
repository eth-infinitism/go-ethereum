package aapool

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
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
	config       Config
	discoverFeed event.Feed                   // Event feed to send out new tx events on pool inclusion (reorg included)
	currentHead  atomic.Pointer[types.Header] // Current head of the blockchain

	pendingBundles  []*types.ExternallyReceivedBundle
	includedBundles map[common.Hash]*types.BundleReceipt

	mu sync.Mutex
}

func (pool *AccountAbstractionBundlerPool) Init(_ *big.Int, head *types.Header, _ txpool.AddressReserver) error {
	pool.pendingBundles = make([]*types.ExternallyReceivedBundle, 0)
	pool.currentHead.Store(head)
	return nil
}

func (pool *AccountAbstractionBundlerPool) Close() error {
	return nil
}

func (pool *AccountAbstractionBundlerPool) Reset(oldHead, newHead *types.Header) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pendingBundles := make([]*types.ExternallyReceivedBundle, 0, len(pool.pendingBundles))
	for _, bundle := range pool.pendingBundles {
		nextBlock := big.NewInt(0).Add(newHead.Number, big.NewInt(1))
		if bundle.ValidForBlock.Cmp(nextBlock) == 0 {
			pendingBundles = append(pendingBundles, bundle)
		}
	}
	pool.pendingBundles = pendingBundles
	pool.currentHead.Store(newHead)
	fmt.Printf("\nALEXF: AAPool Reset OldHead:%s NewHead:%s PendingBundles:%d",
		oldHead.Number.String(),
		newHead.Number.String(),
		len(pool.pendingBundles),
	)
}

// SetGasTip is ignored by the External Bundler AA sub pool.
func (pool *AccountAbstractionBundlerPool) SetGasTip(_ *big.Int) {}

func (pool *AccountAbstractionBundlerPool) Has(hash common.Hash) bool {
	tx := pool.Get(hash)
	return tx != nil
}

func (pool *AccountAbstractionBundlerPool) Get(hash common.Hash) *types.Transaction {
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
	return pool.selectExternalBundle(), nil
}

// SubscribeTransactions is not needed for the External Bundler AA sub pool and 'ch' will never be sent anything.
func (pool *AccountAbstractionBundlerPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, _ bool) event.Subscription {
	return pool.discoverFeed.Subscribe(ch)
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
func New(config Config) *AccountAbstractionBundlerPool {
	return &AccountAbstractionBundlerPool{
		config: config,
	}
}

// Filter rejects all individual transactions for External Bundler AA sub pool.
func (pool *AccountAbstractionBundlerPool) Filter(_ *types.Transaction) bool {
	return false
}

func (pool *AccountAbstractionBundlerPool) SubmitBundle(bundle *types.ExternallyReceivedBundle) error {
	currentBlock := pool.currentHead.Load().Number
	nextBlock := big.NewInt(0).Add(currentBlock, big.NewInt(1))
	if nextBlock.Cmp(bundle.ValidForBlock) == 0 {
		pool.pendingBundles = append(pool.pendingBundles, bundle)
		return nil
	}
	return errors.New(fmt.Sprintf("submitted bundle valid for block: %s; next block: %s",
		bundle.ValidForBlock.String(), nextBlock.String()))
}

func (pool *AccountAbstractionBundlerPool) GetBundleStats(hash common.Hash) (*types.BundleReceipt, error) {
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
