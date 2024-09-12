package core

import "github.com/ethereum/go-ethereum/common"

const PaymasterMaxContextSize = 65536
const Rip7560AbiVersion = 0

var AA_ENTRY_POINT = common.HexToAddress("0x0000000000000000000000000000000000007560")
var AA_SENDER_CREATOR = common.HexToAddress("0x00000000000000000000000000000000ffff7560")

// AA_GAS_PENALTY_PCT is always applied to unused execution and postOp gas limits
const AA_GAS_PENALTY_PCT = 10

const Rip7560AbiJson = `
[
	{
		"type":"function",
		"name":"validateTransaction",
		"inputs": [
			{"name": "version","type": "uint256"},
			{"name": "txHash","type": "bytes32"},
			{"name": "transaction","type": "bytes"}
		]
	},
	{
		"type":"function",
		"name":"validatePaymasterTransaction",
		"inputs": [
			{"name": "version","type": "uint256"},
			{"name": "txHash","type": "bytes32"},
			{"name": "transaction","type": "bytes"}
		]
	},
	{
		"type":"function",
		"name":"postPaymasterTransaction",
		"inputs": [
			{"name": "success","type": "bool"},
			{"name": "actualGasCost","type": "uint256"},
			{"name": "context","type": "bytes"}
		]
	},
	{
		"type":"function",
		"name":"acceptAccount",
		"inputs": [
			{"name": "validAfter","type": "uint256"},
			{"name": "validUntil","type": "uint256"}
		]
	},
	{
		"type":"function",
		"name":"acceptPaymaster",
		"inputs": [
			{"name": "validAfter","type": "uint256"},
			{"name": "validUntil","type": "uint256"},
			{"name": "context","type": "bytes"}
		]
	},
	{
		"type":"function",
		"name":"sigFailAccount",
		"inputs": [
			{"name": "validAfter","type": "uint256"},
			{"name": "validUntil","type": "uint256"}
		]
	},
	{
		"type":"function",
		"name":"sigFailPaymaster",
		"inputs": [
			{"name": "validAfter","type": "uint256"},
			{"name": "validUntil","type": "uint256"},
			{"name": "context","type": "bytes"}
		]
	},
	{
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "sender",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "paymaster",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "nonceKey",
          "type": "uint256"
        },
{
          "indexed": false,
          "internalType": "uint256",
          "name": "nonceSequence",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "bool",
          "name": "executionStatus",
          "type": "uint256"
        }
      ],
      "name": "RIP7560TransactionEvent",
      "type": "event"
    },
 	{
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "sender",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "nonceKey",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "nonceSequence",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "bytes",
          "name": "revertReason",
          "type": "bytes"
        }
      ],
      "name": "RIP7560TransactionRevertReason",
      "type": "event"
    },
	{
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "sender",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "paymaster",
          "type": "address"
        },
        {
          "indexed": false,
          "internalType": "uint256",
          "name": "nonceKey",
          "type": "uint256"
        },
{
          "indexed": false,
          "internalType": "uint256",
          "name": "nonceSequence",
          "type": "uint256"
        },
        {
          "indexed": false,
          "internalType": "bytes",
          "name": "revertReason",
          "type": "bytes"
        }
      ],
      "name": "RIP7560TransactionPostOpRevertReason",
      "type": "event"
    },
	{
      "anonymous": false,
      "inputs": [
        {
          "indexed": true,
          "internalType": "address",
          "name": "sender",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "paymaster",
          "type": "address"
        },
        {
          "indexed": true,
          "internalType": "address",
          "name": "deployer",
          "type": "address"
        }
      ],
      "name": "RIP7560AccountDeployed",
      "type": "event"
    }
]`
