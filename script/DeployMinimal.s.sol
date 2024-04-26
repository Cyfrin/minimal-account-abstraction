// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Script, console2 } from "forge-std/Script.sol";
import { MinimalAccount } from "src/ethereum/MinimalAccount.sol";

contract DeployMinimal is Script {
    function run() public {
        vm.startBroadcast();
        deploy();
        vm.stopBroadcast();
    }

    function deploy() public returns (MinimalAccount) {
        MinimalAccount minimalAccount = new MinimalAccount();
        return minimalAccount;
    }
}
