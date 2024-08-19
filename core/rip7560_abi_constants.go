package core

const PaymasterMaxContextSize = 65536
const Rip7560AbiVersion = 0
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
	}
]`
