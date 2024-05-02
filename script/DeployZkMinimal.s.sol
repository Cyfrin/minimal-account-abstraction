// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Script, console2 } from "forge-std/Script.sol";
import { ZkMinimalAccount } from "src/zkSync/ZkMinimalAccount.sol";
import { HelperConfig } from "./HelperConfig.s.sol";

contract DeployZkMinimal is Script {
    function run() public {
        vm.startBroadcast();
        deploy();
        vm.stopBroadcast();
    }

    function deploy() public returns (ZkMinimalAccount) {
        ZkMinimalAccount minimalAccount = new ZkMinimalAccount();
        minimalAccount.transferOwnership(msg.sender);
        return minimalAccount;
    }
}
