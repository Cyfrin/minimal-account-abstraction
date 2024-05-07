// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Script, console2 } from "forge-std/Script.sol";
import { DefaultAccount } from "@matterlabs/zksync-contracts/l2/system-contracts/DefaultAccount.sol";

contract DeployDefaultAccount is Script {
    function run() public {
        vm.startBroadcast();
        deploy();
        vm.stopBroadcast();
    }

    function deploy() public returns (DefaultAccount) {
        DefaultAccount defaultAccount = new DefaultAccount();
        return defaultAccount;
    }
}
