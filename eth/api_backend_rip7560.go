package eth

import (
	"context"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func (b *EthAPIBackend) SubmitRip7560Bundle(bundle *types.ExternallyReceivedBundle) error {
	if !b.rip7560AcceptPush {
		return errors.New("illegal call to eth_sendRip7560TransactionsBundle: Config.Eth.Rip7560AcceptPush is not set")
	}
	return b.eth.txPool.SubmitRip7560Bundle(bundle)
}

func (b *EthAPIBackend) GetRip7560BundleStatus(ctx context.Context, hash common.Hash) (*types.BundleReceipt, error) {
	return b.eth.txPool.GetRip7560BundleStatus(hash)
}

// GetRip7560TransactionDebugInfo debug method for RIP-7560
func (b *EthAPIBackend) GetRip7560TransactionDebugInfo(hash common.Hash) (map[string]interface{}, error) {
	info := b.eth.blockchain.GetRip7560TransactionDebugInfo(hash)
	if info == nil {
		return nil, nil
	}
	return map[string]interface{}{
		"transactionHash":  hash,
		"revertEntityName": info.RevertEntityName,
		"revertData":       info.RevertData,
		"frameReverted":    info.FrameReverted,
	}, nil
}

// SetRip7560TransactionDebugInfo debug method for RIP-7560
func (b *EthAPIBackend) SetRip7560TransactionDebugInfo(infos []*types.Rip7560TransactionDebugInfo) {
	b.eth.blockchain.SetRip7560TransactionDebugInfo(infos)
}
