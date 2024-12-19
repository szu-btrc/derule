# Derule

This is the codebase of **Derule**, a blockchain-based decentralized rule engine framework
that can efficiently support complex and large-scale Web3.0 applications. Derule 
can efficiently execute intricate business logic rules in DApps and supports online 
rule updates to cope with changing business requirements.

## Code

Derule is based on geth (https://github.com/ethereum/go-ethereum.git) v1.9.25-stable

The Go files in this rep are modified EVM source code:
- contracts.go replaces ethereum/go-ethereum/core/vm/contracts.go
- contracts_test.go replaces ethereum/go-ethereum/core/vm/contracts_test.go
- evm.go replaces ethereum/go-ethereum/core/vm/evm.go

**ruletest15.sol** contains the code for the rule engine control contract.

**tupledes.txt** is a template for rule tuple descriptor.




