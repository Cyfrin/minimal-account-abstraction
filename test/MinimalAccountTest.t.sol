// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { MinimalAccount } from "src/ethereum/MinimalAccount.sol";
import { DeployMinimal, HelperConfig } from "script/DeployMinimal.s.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";
import { PackedUserOperation } from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MinimalAccountTest is Test {
    using MessageHashUtils for bytes32;

    MinimalAccount minimalAccount;
    HelperConfig config;
    DeployMinimal deployMinimal;
    MockERC20 mockERC20;
    IEntryPoint entryPoint;
    address user;
    uint256 userKey;
    address payable randomUser;

    function setUp() public {
        config = new HelperConfig();
        deployMinimal = new DeployMinimal();
        mockERC20 = new MockERC20();
        entryPoint = IEntryPoint(config.getConfigByChainId(block.chainid).entryPoint);
        minimalAccount = deployMinimal.deploy(address(entryPoint));
        (user, userKey) = makeAddrAndKey("user");
        randomUser = payable(makeAddr("randomUser"));
    }

    /*
     * This is an example flow of the smart wallet owner calling a function on the smart wallet.
     * This is reminiscent of the flow of a multi-sig contract wallet, with 1 signer.
     */
    function testOwnerCanExecuteCommands() public {
        // Arrange
        assertEq(mockERC20.balanceOf(address(minimalAccount)), 0);
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);

        // Act
        vm.prank(minimalAccount.owner());
        minimalAccount.execute(dest, value, func);

        // Assert
        assertEq(mockERC20.balanceOf(address(minimalAccount)), mockERC20.AMOUNT());
    }

    function testEntryPointCanExecuteCommand() public {
        // Arrange
        assertEq(mockERC20.balanceOf(address(minimalAccount)), 0);
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);
        bytes memory executeCalldata = abi.encodeWithSelector(minimalAccount.execute.selector, dest, value, func);

        // TODO, running this test fails with an EVM revert, but why?
        PackedUserOperation memory userOp = _getSignedOp(executeCalldata, userKey, address(minimalAccount));
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Act
        // A randomUser should be able to call this, as this can be called by anyone who serves the user operation
        // mempool.
        vm.prank(randomUser);
        entryPoint.handleOps(ops, randomUser);

        // Assert
        assertEq(mockERC20.balanceOf(address(minimalAccount)), mockERC20.AMOUNT());
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/
    function _getSignedOp(
        bytes memory callData,
        uint256 privateKey,
        address account
    )
        internal
        view
        returns (PackedUserOperation memory)
    {
        PackedUserOperation memory op = _getUnsignedOp(callData, account);

        bytes32 userOperationHash = entryPoint.getUserOpHash(op);
        bytes32 digest = userOperationHash.toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        op.signature = abi.encodePacked(v, r, s);
        return op;
    }

    function _getUnsignedOp(
        bytes memory callData,
        address account
    )
        internal
        pure
        returns (PackedUserOperation memory)
    {
        uint128 verificationGasLimit = 1 << 24; // 16_777_216, this number is commonly chosen cuz it's "pretty good" as
            // a gas limit
        uint128 callGasLimit = 1 << 24;
        uint128 maxPriorityFeePerGas = 1 << 8;
        uint128 maxFeePerGas = 1 << 8;
        return PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: callData,
            // This is how we concat the two variables into one bytes32. This is what's needed for our struct.
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: 1 << 24,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: "",
            signature: ""
        });
    }
}
