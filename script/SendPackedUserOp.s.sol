// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { PackedUserOperation } from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { HelperConfig } from "script/HelperConfig.s.sol";
import { IEntryPoint } from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { MinimalAccount } from "src/ethereum/MinimalAccount.sol";

contract SendPackedUserOp is Script {
    using MessageHashUtils for bytes32;

    // CHANGE THIS!
    address public constant MY_ACCOUNT_ADDRESS = 0x03Ad95a54f02A40180D45D76789C448024145aaF;

    // This is a test Patrick account 😊
    address payable public constant SOMEONE_TO_APPROVE = payable(0x9EA9b0cc1919def1A3CfAEF4F7A66eE3c36F86fC);
    uint256 public constant AMOUNT_TO_APPROVE = 1e6;

    HelperConfig helperConfig;

    function run() public {
        helperConfig = new HelperConfig();
        address dest = helperConfig.getConfigByChainId(block.chainid).usdc;
        uint256 value = 0;
        bytes memory funcData = abi.encodeWithSelector(IERC20.approve.selector, SOMEONE_TO_APPROVE, AMOUNT_TO_APPROVE);
        bytes memory executeCalldata = abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, funcData);

        // Don't do this, it's for demo purposes only. Always use an encrypted key.
        // Ideally, you'd sign your transaction with a cast bash script.
        PackedUserOperation memory userOp = _getSignedOp(executeCalldata, vm.envUint("SMALL_MONEY_KEY"));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Act
        // Any user operation mempool nodes should be able to call this function.
        vm.startBroadcast();
        IEntryPoint(helperConfig.getConfigByChainId(block.chainid).entryPoint).handleOps(ops, SOMEONE_TO_APPROVE);
        vm.stopBroadcast();
    }

    function _getSignedOp(bytes memory callData, uint256 privateKey) internal returns (PackedUserOperation memory) {
        PackedUserOperation memory op = _getUnsignedOp(callData);

        // This method returns the hash of the struct WITHOUT the signature.
        bytes32 userOperationHash =
            IEntryPoint(helperConfig.getConfigByChainId(block.chainid).entryPoint).getUserOpHash(op);
        bytes32 digest = userOperationHash.toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        op.signature = abi.encodePacked(r, s, v); // Note the order!
        return op;
    }

    function _getUnsignedOp(bytes memory callData) internal pure returns (PackedUserOperation memory) {
        // 16_777_216, this number is commonly chosen cuz it's "pretty good" as
        // This is some clever shifting bit stuff to make numbers
        uint128 verificationGasLimit = 1 << 24;
        // a gas limit
        uint128 callGasLimit = 1 << 24;
        uint128 maxPriorityFeePerGas = 1 << 8;
        uint128 maxFeePerGas = 1 << 8;
        return PackedUserOperation({
            sender: address(MY_ACCOUNT_ADDRESS),
            nonce: 0,
            initCode: "",
            callData: callData,
            // This is how we concat the two variables into one bytes32. This is what's needed for our struct.
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: 1 << 24,
            // This is how we concat the two variables into one bytes32. This is what's needed for our struct.
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: "",
            signature: ""
        });
    }
}
