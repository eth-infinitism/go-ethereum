curl -s http://localhost:350{0,1}/eth/v1/node/peers

curl -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"admin_peers","params":[],"id":1}' localhost:854{5,7}
