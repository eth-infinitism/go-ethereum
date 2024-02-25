package types

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

type rip7560Signer struct{ londonSigner }

func NewRIP7560Signer(chainId *big.Int) Signer {
	return rip7560Signer{londonSigner{eip2930Signer{NewEIP155Signer(chainId)}}}
}

func (s rip7560Signer) Sender(tx *Transaction) (common.Address, error) {
	if tx.Type() != Rip7560Type {
		return s.londonSigner.Sender(tx)
	}
	V, R, S := tx.RawSignatureValues()
	// DynamicFee txs are defined to use 0 and 1 as their recovery
	// id, add 27 to become equivalent to unprotected Homestead signatures.
	//V = new(big.Int).Add(V, big.NewInt(27))
	if tx.ChainId().Cmp(s.chainId) != 0 {
		return common.Address{}, fmt.Errorf("%w: have %d want %d", ErrInvalidChainId, tx.ChainId(), s.chainId)
	}
	hash := s.Hash(tx)
	println("TX HASH = ")
	println(hex.EncodeToString(hash[:]))
	address, err := recoverPlain(hash, R, S, V, true)
	println("TX SIGNER = ")
	println(address.String())
	if err != nil {
		return common.Address{}, err
	}
	if address.Cmp(*tx.Rip7560TransactionData().Sender) != 0 {
		return common.Address{}, errors.New("recovered signature does not match the claimed EOA sender")
	}

	return address, err
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s rip7560Signer) Hash(tx *Transaction) common.Hash {
	if tx.Type() != Rip7560Type {
		return s.londonSigner.Hash(tx)
	}
	aatx := tx.Rip7560TransactionData()
	return prefixedRlpHash(
		tx.Type(),
		[]interface{}{
			s.chainId,
			tx.GasTipCap(),
			tx.GasFeeCap(),
			tx.Gas(),
			//tx.To(),
			tx.Data(),
			tx.AccessList(),

			aatx.Sender,
			aatx.PaymasterData,
			aatx.DeployerData,
			aatx.BuilderFee,
			aatx.ValidationGas,
			aatx.PaymasterGas,
			aatx.BigNonce,
		})
}
