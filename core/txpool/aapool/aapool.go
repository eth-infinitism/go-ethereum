package aapool

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/blobpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"math/big"
)

// AccountAbstractionPool is the transaction pool dedicated to RIP-7560 AA transactions.
type AlexfAccountAbstractionPool struct {
	discoverFeed event.Feed // Event feed to send out new tx events on pool inclusion (reorg included)
}

func (p *AlexfAccountAbstractionPool) Init(gasTip *big.Int, head *types.Header, reserve txpool.AddressReserver) error {
	//TODO implement me
	//panic("implement me")
	return nil
}

func (p *AlexfAccountAbstractionPool) Close() error {
	//TODO implement me
	panic("implement me")
}

func (p *AlexfAccountAbstractionPool) Reset(oldHead, newHead *types.Header) {
	//TODO implement me
	//panic("implement me")
	return
}

func (p *AlexfAccountAbstractionPool) SetGasTip(tip *big.Int) {
	//TODO implement me
	panic("implement me")
}

func (p *AlexfAccountAbstractionPool) Has(hash common.Hash) bool {
	//TODO implement me
	panic("implement me")
}

func (p *AlexfAccountAbstractionPool) Get(hash common.Hash) *types.Transaction {
	//TODO implement me
	//panic("implement me")
	return nil
}

func (p *AlexfAccountAbstractionPool) Add(txs []*types.Transaction, local bool, sync bool) []error {
	//TODO implement me
	//panic("implement me")
	var (
		adds = make([]*types.Transaction, 0, len(txs))
		errs = make([]error, len(txs))
	)
	for i, tx := range txs {
		errs[i] = p.add(tx)
		if errs[i] == nil {
			adds = append(adds, tx.WithoutBlobTxSidecar())
		}
	}
	if len(adds) > 0 {
		p.discoverFeed.Send(core.NewTxsEvent{Txs: adds})
		//p.insertFeed.Send(core.NewTxsEvent{Txs: adds})
	}
	return errs
}

func (p *AlexfAccountAbstractionPool) add(tx *types.Transaction) (err error) {
	return nil
}

func (p *AlexfAccountAbstractionPool) Pending(enforceTips bool) map[common.Address][]*txpool.LazyTransaction {
	//TODO implement me
	pending := make(map[common.Address][]*txpool.LazyTransaction)
	return pending
}

func (p *AlexfAccountAbstractionPool) SubscribeTransactions(ch chan<- core.NewTxsEvent, reorgs bool) event.Subscription {
	//TODO implement me
	return p.discoverFeed.Subscribe(ch)
}

func (p *AlexfAccountAbstractionPool) Nonce(addr common.Address) uint64 {
	//TODO implement me
	panic("implement me")
}

func (p *AlexfAccountAbstractionPool) Stats() (int, int) {
	//TODO implement me
	panic("implement me")
}

func (p *AlexfAccountAbstractionPool) Content() (map[common.Address][]*types.Transaction, map[common.Address][]*types.Transaction) {
	//TODO implement me
	panic("implement me")
}

func (p *AlexfAccountAbstractionPool) ContentFrom(addr common.Address) ([]*types.Transaction, []*types.Transaction) {
	//TODO implement me
	panic("implement me")
}

func (p *AlexfAccountAbstractionPool) Locals() []common.Address {
	//TODO implement me
	return []common.Address{}
}

func (p *AlexfAccountAbstractionPool) Status(hash common.Hash) txpool.TxStatus {
	//TODO implement me
	panic("implement me")
}

// New creates a new blob transaction pool to gather, sort and filter inbound
// blob transactions from the network.
func New(config blobpool.Config, chain blobpool.BlockChain) *AlexfAccountAbstractionPool {
	// Sanitize the input to ensure no vulnerable gas prices are set
	//config = (&config).sanitize()

	// Create the transaction pool with its initial settings
	return &AlexfAccountAbstractionPool{
		//config: config,
		//signer: types.LatestSigner(chain.Config()),
		//chain:  chain,
		//lookup: make(map[common.Hash]uint64),
		//index:  make(map[common.Address][]*blobTxMeta),
		//spent:  make(map[common.Address]*uint256.Int),
	}
}

// Filter returns whether the given transaction can be consumed by the blob pool.
func (p *AlexfAccountAbstractionPool) Filter(tx *types.Transaction) bool {
	return tx.Type() == types.ALEXF_AA_TX_TYPE
}
