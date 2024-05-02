-include .env

.PHONY: all test clean deploy fund help install snapshot format anvil scopefile

DEFAULT_ANVIL_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

all: remove install build

# Clean the repo
clean  :; forge clean

# Remove modules
remove :; rm -rf .gitmodules && rm -rf .git/modules/* && rm -rf lib && touch .gitmodules && git add . && git commit -m "modules"

install :; forge install foundry-rs/forge-std --no-commit && forge install openzeppelin/openzeppelin-contracts --no-commit && forge install eth-infinitism/account-abstraction --no-commit && forge install cyfrin/zksync-contracts --no-commit 

# Update Dependencies
update:; forge update

format :; forge fmt

anvil :; anvil -m 'test test test test test test test test test test test junk' --steps-tracing --block-time 1

slither :; slither . --config-file slither.config.json --checklist 

scope :; tree ./src/ | sed 's/└/#/g; s/──/--/g; s/├/#/g; s/│ /|/g; s/│/|/g'

scopefile :; @tree ./src/ | sed 's/└/#/g' | awk -F '── ' '!/\.sol$$/ { path[int((length($$0) - length($$2))/2)] = $$2; next } { p = "src"; for(i=2; i<=int((length($$0) - length($$2))/2); i++) if (path[i] != "") p = p "/" path[i]; print p "/" $$2; }' > scope.txt

aderyn :; aderyn .

# /*//////////////////////////////////////////////////////////////
#                               EVM
# //////////////////////////////////////////////////////////////*/

build:; forge build 

test :; forge test

testFork :; forge test --fork-url mainnet

snapshot :; forge snapshot 

# /*//////////////////////////////////////////////////////////////
#                          EVM - SCRIPTS
# //////////////////////////////////////////////////////////////*/

# How we got the mock entrypoint contract so quick
getEntryPoint :; forge clone -c 1 --etherscan-api-key ${ETHERSCAN_API_KEY} 0x0000000071727De22E5E9d8BAf0edAc6f37da032 --no-git

flattenClone :; forge flatten src/core/EntryPoint.sol > MockEntryPoint.sol

deployEth :; forge script script/DeployMinimal.s.sol --rpc-url arbitrum --sender ${SMALL_MONEY_SENDER} --account smallmoney --broadcast --verify -vvvv

verify :; forge verify-contract --etherscan-api-key ${ETHERSCAN_API_KEY} --rpc-url ${MAINNET_RPC_URL} XXX <PATH_TO_CONTRACT>

getCalldata :; cast calldata "approve(address,uint256)" 0x9EA9b0cc1919def1A3CfAEF4F7A66eE3c36F86fC 100000000000000000000

estimate :; cast estimate "approve(address,uint256)" "approve(address,uint256)" 0x9EA9b0cc1919def1A3CfAEF4F7A66eE3c36F86fC 100000000000000000000

sendUserOp :; forge script script/SendPackedUserOp.s.sol --rpc-url arbitrum --sender ${SMALL_MONEY_SENDER} --account smallmoney --broadcast -vvvv

# /*//////////////////////////////////////////////////////////////
#                              ZKSYNC
# //////////////////////////////////////////////////////////////*/

buildZk:; forge build --zksync --via-ir

testZk :; forge test --zksync --via-ir

testForkZk :; forge test --zksync --via-ir

snapshotZk :; forge snapshot --zksync --via-ir

# /*//////////////////////////////////////////////////////////////
#                         ZKSYNC -SCRIPTS
# //////////////////////////////////////////////////////////////*/