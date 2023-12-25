package aapool

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
)

// BigNoncer
// TODO: implement 2D nonce management here
//
//	for all senders in the pool, keep the current nonce; update on each 'reset'
type BigNoncer struct {
	noncePerSenderPerKey map[common.Address]map[string]uint64
	evm                  *core.BlockChain
}

