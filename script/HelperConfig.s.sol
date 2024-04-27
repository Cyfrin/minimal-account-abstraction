// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { Script } from "forge-std/Script.sol";
import { MockEntryPoint } from "test/mocks/MockEntryPoint.sol";
import { console2 } from "forge-std/console2.sol";

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
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    uint256 constant ETH_MAINNET_CHAIN_ID = 1;
    uint256 constant ZKSYNC_MAINNET_CHAIN_ID = 324;
    uint256 constant ZKSYNC_SEPOLIA_CHAIN_ID = 300;

    // Local network state variables
    NetworkConfig localNetworkConfig;

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    constructor() { }

    function getConfigByChainId(uint256 chainId) public returns (NetworkConfig memory) {
        if (chainId == ZKSYNC_MAINNET_CHAIN_ID) {
            return getZkSyncConfig();
        } else if (chainId == ZKSYNC_SEPOLIA_CHAIN_ID) {
            return getZkSyncSepoliaConfig();
        } else if (chainId == ETH_MAINNET_CHAIN_ID) {
            return getEthMainnetConfig();
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
        return NetworkConfig({ entryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032 });
    }

    function getZkSyncConfig() public pure returns (NetworkConfig memory) {
        return NetworkConfig({ entryPoint: address(0) }); // zkSync supports native AA, so no entry point needed
    }

    function getZkSyncSepoliaConfig() public pure returns (NetworkConfig memory) {
        return NetworkConfig({ entryPoint: address(0) }); // zkSync supports native AA, so no entry point needed
    }

    function getOrCreateAnvilEthConfig() public returns (NetworkConfig memory) {
        if (localNetworkConfig.entryPoint != address(0)) {
            return localNetworkConfig;
        }

        MockEntryPoint entryPoint = new MockEntryPoint();
        console2.log("Created new entry point: ", address(entryPoint));
        localNetworkConfig = NetworkConfig({ entryPoint: address(entryPoint) });
        return localNetworkConfig;
    }
}
