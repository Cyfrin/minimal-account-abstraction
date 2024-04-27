// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Script, console2 } from "forge-std/Script.sol";
import { MinimalAccount } from "src/ethereum/MinimalAccount.sol";
import { HelperConfig } from "./HelperConfig.s.sol";

contract DeployMinimal is Script {
    function run() public {
        HelperConfig config = new HelperConfig();
        address entryPoint = config.getConfigByChainId(block.chainid).entryPoint;

        vm.startBroadcast();
        deploy(entryPoint);
        vm.stopBroadcast();
    }

    function deploy(address entryPoint) public returns (MinimalAccount) {
        MinimalAccount minimalAccount = new MinimalAccount(entryPoint);
        return minimalAccount;
    }
}
