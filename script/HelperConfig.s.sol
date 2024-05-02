// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { Script } from "forge-std/Script.sol";
import { MockEntryPoint } from "test/mocks/MockEntryPoint.sol";
import { console2 } from "forge-std/console2.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";

contract HelperConfig is Script {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/
    error HelperConfig__InvalidChainId();

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/
    struct NetworkConfig {
        address entryPoint;
        address usdc;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    uint256 constant ETH_MAINNET_CHAIN_ID = 1;
    uint256 constant ZKSYNC_MAINNET_CHAIN_ID = 324;
    uint256 constant ZKSYNC_SEPOLIA_CHAIN_ID = 300;
    uint256 constant ARBITRUM_MAINNET_CHAIN_ID = 42_161;

    // Local network state variables
    NetworkConfig localNetworkConfig;
    mapping(uint256 chainId => NetworkConfig) public networkConfigs;

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    constructor() {
        networkConfigs[ETH_MAINNET_CHAIN_ID] = getEthMainnetConfig();
        networkConfigs[ZKSYNC_MAINNET_CHAIN_ID] = getZkSyncConfig();
        networkConfigs[ARBITRUM_MAINNET_CHAIN_ID] = getArbMainnetConfig();
    }

    function getConfigByChainId(uint256 chainId) public returns (NetworkConfig memory) {
        if (networkConfigs[chainId].entryPoint != address(0)) {
            return networkConfigs[chainId];
        } else {
            return getOrCreateAnvilEthConfig();
        }
    }

    function getActiveNetworkConfig() public returns (NetworkConfig memory) {
        return getConfigByChainId(block.chainid);
    }

    /*//////////////////////////////////////////////////////////////
                                CONFIGS
    //////////////////////////////////////////////////////////////*/
    function getEthMainnetConfig() public pure returns (NetworkConfig memory) {
        // This was the v0.6 address
        // return NetworkConfig({ entryPoint: 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789 });
        return NetworkConfig({
            entryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032,
            usdc: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
        });
        // https://blockscan.com/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032
    }

    function getZkSyncConfig() public pure returns (NetworkConfig memory) {
        return NetworkConfig({ entryPoint: address(0), usdc: 0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4 }); // zkSync
            // supports native AA, so no entry point needed
    }

    function getZkSyncSepoliaConfig() public pure returns (NetworkConfig memory) {
        // usdc isn't deployed on zkSync sepolia
        return NetworkConfig({ entryPoint: address(0), usdc: 0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4 }); // zkSync
            // supports native AA, so no entry point needed
    }

    function getArbMainnetConfig() public pure returns (NetworkConfig memory) {
        return NetworkConfig({
            entryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032,
            usdc: 0xaf88d065e77c8cC2239327C5EDb3A432268e5831
        });
    }

    function getOrCreateAnvilEthConfig() public returns (NetworkConfig memory) {
        if (localNetworkConfig.entryPoint != address(0)) {
            return localNetworkConfig;
        }

        console2.log(unicode"⚠️ You have deployed a mock conract!");
        console2.log("Make sure this was intentional");

        MockEntryPoint entryPoint = new MockEntryPoint();
        console2.log("Created new entry point: ", address(entryPoint));
        MockERC20 usdc = new MockERC20();
        console2.log("Created new USDC: ", address(usdc));
        localNetworkConfig = NetworkConfig({ entryPoint: address(entryPoint), usdc: address(usdc) });
        return localNetworkConfig;
    }
}
