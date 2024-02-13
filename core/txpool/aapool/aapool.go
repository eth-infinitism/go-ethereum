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
)

type Config struct {
	// nonce manager address
	// ops per staked/unstaked ACC/PM/DEPL
	// max validation gas limit
}

// AlexfAccountAbstractionPool is the transaction pool dedicated to RIP-7560 AA transactions.
type AlexfAccountAbstractionPool struct {
	discoverFeed event.Feed // Event feed to send out new tx events on pool inclusion (reorg included)

	pendingBundles  []*types.ExternallyReceivedBundle
	includedBundles map[common.Hash]*types.BundleReceipt

	mu sync.Mutex
}

func (pool *AlexfAccountAbstractionPool) Init(_ *big.Int, _ *types.Header, _ txpool.AddressReserver) error {
	pool.pendingBundles = make([]*types.ExternallyReceivedBundle, 0)
	return nil
}

func (pool *AlexfAccountAbstractionPool) Close() error {
	return nil
}

func (pool *AlexfAccountAbstractionPool) Reset(oldHead, newHead *types.Header) {
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
	fmt.Printf("\nALEXF: AAPool Reset OldHead:%s NewHead:%s PendingBundles:%d",
		oldHead.Number.String(),
		newHead.Number.String(),
		len(pool.pendingBundles),
	)
}

// SetGasTip is ignored by the External Bundler AA sub pool
func (pool *AlexfAccountAbstractionPool) SetGasTip(_ *big.Int) {}

func (pool *AlexfAccountAbstractionPool) Has(hash common.Hash) bool {
	tx := pool.Get(hash)
	return tx != nil
}

func (pool *AlexfAccountAbstractionPool) Get(hash common.Hash) *types.Transaction {
	for _, bundle := range pool.pendingBundles {
		for _, tx := range bundle.Transactions {
			if tx.Hash().Cmp(hash) == 0 {
				return tx
			}
		}
	}
	return nil
}

func (pool *AlexfAccountAbstractionPool) Add(_ []*types.Transaction, _ bool, _ bool) []error {
	return nil
}

func (pool *AlexfAccountAbstractionPool) Pending(_ bool) map[common.Address][]*txpool.LazyTransaction {
	return nil
}
func (pool *AlexfAccountAbstractionPool) PendingBundle() (*types.ExternallyReceivedBundle, error) {
	return pool.selectExternalBundle(), nil
}

// SubscribeTransactions is not needed for the External Bundler AA sub pool and 'ch' will never be sent anything
func (pool *AlexfAccountAbstractionPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	return pool.discoverFeed.Subscribe(ch)
}

// Nonce is only used from 'GetPoolNonce' which is not relevant for AA transactions
func (pool *AlexfAccountAbstractionPool) Nonce(addr common.Address) uint64 {
	return 0
}

// Stats function not implemented for the External Bundler AA sub pool
func (pool *AlexfAccountAbstractionPool) Stats() (int, int) {
	return 0, 0
}

// Content function not implemented for the External Bundler AA sub pool
func (pool *AlexfAccountAbstractionPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	return nil, nil
}

// ContentFrom function not implemented for the External Bundler AA sub pool
func (pool *AlexfAccountAbstractionPool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	return nil, nil
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
		//chain:       chain,
		//chainConfig: chainConfig,
		//lookup: make(map[common.Hash]uint64),
		//index:  make(map[common.Address][]*blobTxMeta),
		//spent:  make(map[common.Address]*uint256.Int),
	}
}

// Filter rejects all individual transactions for External Bundler AA sub pool
func (pool *AlexfAccountAbstractionPool) Filter(_ *types.Transaction) bool {
	return false
}

func (pool *AlexfAccountAbstractionPool) SubmitBundle(bundle *types.ExternallyReceivedBundle) {
	pool.pendingBundles = append(pool.pendingBundles, bundle)
}

func (pool *AlexfAccountAbstractionPool) GetBundleStats(hash common.Hash) (*types.BundleReceipt, error) {
	return pool.includedBundles[hash], nil
}

// Simply returns the bundle with the highest promised revenue by fully trusting the bundler-provided value
func (pool *AlexfAccountAbstractionPool) selectExternalBundle() *types.ExternallyReceivedBundle {
	var selectedBundle *types.ExternallyReceivedBundle
	for _, bundle := range pool.pendingBundles {
		if selectedBundle == nil || selectedBundle.ExpectedRevenue.Cmp(bundle.ExpectedRevenue) == -1 {
			selectedBundle = bundle
		}
	}
	return selectedBundle
}
