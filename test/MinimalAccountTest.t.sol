// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test, console2 } from "forge-std/Test.sol";
import { MinimalAccount } from "src/ethereum/MinimalAccount.sol";
import { DeployMinimal, HelperConfig } from "script/DeployMinimal.s.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";
import { PackedUserOperation } from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { ValidationData } from "lib/account-abstraction/contracts/core/Helpers.sol";

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
        (user, userKey) = makeAddrAndKey("user");
        randomUser = payable(makeAddr("randomUser"));
        vm.prank(user);
        minimalAccount = deployMinimal.deploy(address(entryPoint));
        assertEq(minimalAccount.owner(), user);
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
        vm.prank(user);
        // should be the same as vm.prank(minimalAccount.owner());
        minimalAccount.execute(dest, value, func);

        // Assert
        assertEq(mockERC20.balanceOf(address(minimalAccount)), mockERC20.AMOUNT());
    }

    function testNonOwnerCannotExecuteCommands() public {
        // Arrange
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);

        // Act / Assert
        vm.prank(randomUser);
        vm.expectRevert(MinimalAccount.MinimalAccount__NotFromEntryPointOrOwner.selector);
        minimalAccount.execute(dest, value, func);
    }

    // This test is to show you not to be worried about hashing the signed or unsigned operation.
    function testRecoverSignedOp() public view {
        // Arrange
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);
        bytes memory executeCalldata = abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, func);
        PackedUserOperation memory userOpSigned = _getSignedOp(executeCalldata, userKey);
        // Note, it doesn't matter if userOp is signed or unsigned, this function will
        // remove the signature and return the unsigned version.
        bytes32 userOperationHash = entryPoint.getUserOpHash(userOpSigned);

        // Act
        address signer = ECDSA.recover(userOperationHash.toEthSignedMessageHash(), userOpSigned.signature);
        assertEq(signer, user);
    }

    // https://github.com/PatrickAlphaC/signatureVerification/blob/main/src/SignatureVerifierWithOZ.sol#L7
    function testValidationOfUserOps() public {
        // Arrange
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);
        bytes memory executeCalldata = abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, func);
        PackedUserOperation memory userOp = _getSignedOp(executeCalldata, userKey);
        bytes32 userOperationHash = entryPoint.getUserOpHash(userOp);
        uint256 missingAccountFunds = 12_884_901_888; // idk, just a random number

        // Act
        vm.prank(address(entryPoint));
        uint256 validationData = minimalAccount.validateUserOp(userOp, userOperationHash, missingAccountFunds);
        (ValidationData memory data) = _parseValidationData(validationData);
        assertEq(data.aggregator, address(0));
    }

    function testEntryPointCanExecuteCommand() public {
        // Arrange
        assertEq(mockERC20.balanceOf(address(minimalAccount)), 0);
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);
        bytes memory executeCalldata = abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, func);

        PackedUserOperation memory userOp = _getSignedOp(executeCalldata, userKey);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Since we don't have a paymaster, the account has to pay!
        vm.deal(address(minimalAccount), 1e18); // 1e18 is 1 ETH

        // Act
        // Any user operation mempool nodes should be able to call this function.
        vm.prank(randomUser);
        entryPoint.handleOps(ops, randomUser);

        // Assert
        assertEq(mockERC20.balanceOf(address(minimalAccount)), mockERC20.AMOUNT());
    }

    function testNotHavingABalanceFails() public {
        // Arrange
        assertEq(mockERC20.balanceOf(address(minimalAccount)), 0);
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);
        bytes memory executeCalldata = abi.encodeWithSelector(MinimalAccount.execute.selector, dest, value, func);

        PackedUserOperation memory userOp = _getSignedOp(executeCalldata, userKey);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = userOp;

        // Act
        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA21 didn't pay prefund"));
        entryPoint.handleOps(ops, randomUser);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/
    function _getSignedOp(
        bytes memory callData,
        uint256 privateKey
    )
        internal
        view
        returns (PackedUserOperation memory)
    {
        PackedUserOperation memory op = _getUnsignedOp(callData);

        // This method returns the hash of the struct WITHOUT the signature.
        bytes32 userOperationHash = entryPoint.getUserOpHash(op);
        bytes32 digest = userOperationHash.toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        op.signature = abi.encodePacked(r, s, v); // Note the order!
        return op;
    }

    function _getUnsignedOp(bytes memory callData) internal view returns (PackedUserOperation memory) {
        // 16_777_216, this number is commonly chosen cuz it's "pretty good" as
        // This is some clever shifting bit stuff to make numbers
        uint128 verificationGasLimit = 1 << 24;
        // a gas limit
        uint128 callGasLimit = 1 << 24;
        uint128 maxPriorityFeePerGas = 1 << 8;
        uint128 maxFeePerGas = 1 << 8;
        return PackedUserOperation({
            sender: address(minimalAccount),
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

    /**
     * Extract sigFailed, validAfter, validUntil.
     * Also convert zero validUntil to type(uint48).max.
     * @param validationData - The packed validation data.
     */
    function _parseValidationData(uint256 validationData) internal pure returns (ValidationData memory data) {
        address aggregator = address(uint160(validationData));
        uint48 validUntil = uint48(validationData >> 160);
        if (validUntil == 0) {
            validUntil = type(uint48).max;
        }
        uint48 validAfter = uint48(validationData >> (48 + 160));
        return ValidationData(aggregator, validAfter, validUntil);
    }
}
