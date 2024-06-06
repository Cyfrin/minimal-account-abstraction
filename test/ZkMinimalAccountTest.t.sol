// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { ZkMinimalAccount } from "src/zkSync/ZkMinimalAccount.sol";
import { DeployZkMinimal } from "script/DeployZkMinimal.s.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";
import {
    EIP_1559_TX_TYPE,
    Transaction,
    MemoryTransactionHelper
} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
import { BOOTLOADER_FORMAL_ADDRESS } from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ACCOUNT_VALIDATION_SUCCESS_MAGIC } from
    "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import { ZkSyncChainChecker } from "lib/foundry-devops/src/ZkSyncChainChecker.sol";

import { console2 } from "forge-std/console2.sol";

contract ZkMinimalAccountTest is Test, ZkSyncChainChecker {
    using MemoryTransactionHelper for Transaction;
    using MessageHashUtils for bytes32;

    address TEST_BOOTLOADER_FORMAL_ADDRESS = 0x0000000000000000000000000000000000009001; // dummy address
    uint256 PAY_FOR_TRANSACTION_VALUE = 1e18;

    DeployZkMinimal deployer;
    ZkMinimalAccount minimalAccount;
    MockERC20 mockERC20;
    address user;
    uint256 userKey;
    address payable randomUser;

    bytes32 constant EMPTY_BYTES32 = bytes32(0);
    uint8 constant ZKSYNC_AA_TX_TYPE = 0x71;

    function setUp() public {
        deployer = new DeployZkMinimal();
        mockERC20 = new MockERC20();
        (user, userKey) = makeAddrAndKey("user");
        randomUser = payable(makeAddr("randomUser"));

        // --zksync doesn't work well with scripts
        if (!isZkSyncChain()) {
            vm.prank(user);
            minimalAccount = deployer.deploy();
        } else {
            vm.prank(user);
            minimalAccount = new ZkMinimalAccount();
        }

        // Give to our minimalAccount to pay for the account abstraction
        vm.deal(address(minimalAccount), PAY_FOR_TRANSACTION_VALUE);
        assertEq(minimalAccount.owner(), user);
    }

    /*
     * This is an example flow of the smart wallet owner calling a function on the smart wallet.
     * This is reminiscent of the flow of a multi-sig contract wallet, with 1 signer.
     */
    function testZkOwnerCanExecuteCommands() public {
        // Arrange
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);

        // Signature doesn't matter since it's the owner calling
        Transaction memory transaction = _getUnsignedTransaction(user, EIP_1559_TX_TYPE, dest, value, func);

        // Act
        vm.prank(user);
        minimalAccount.executeTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);

        // Assert
        assertEq(mockERC20.balanceOf(address(minimalAccount)), mockERC20.AMOUNT());
    }

    function testZkNonOwnerCantExecuteCommands() public {
        // Arrange
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);

        // Signature doesn't matter since it's the owner calling
        Transaction memory transaction = _getUnsignedTransaction(user, EIP_1559_TX_TYPE, dest, value, func);

        // Act
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.executeTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);

        // Arrange Two
        transaction = _getUnsignedTransaction(randomUser, EIP_1559_TX_TYPE, dest, value, func);
        // Act Two
        vm.prank(randomUser);
        vm.expectRevert();
        minimalAccount.executeTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);
    }

    function testZkValidateTransaction() public {
        // Arrange
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory transaction = _getUnsignedTransaction(user, 0x71, dest, value, func);
        transaction = _signTransaction(transaction, userKey);

        console2.logBytes(transaction.signature);
        console2.logBytes(transaction.data);
        console2.log(transaction.txType);

        // // Act
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        bytes4 magic = minimalAccount.validateTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);

        // Assert
        assertEq(magic, ACCOUNT_VALIDATION_SUCCESS_MAGIC);
    }

    function testZkNonOwnerCanExecuteCommand() public {
        // Arrange
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory transaction = _getUnsignedTransaction(user, ZKSYNC_AA_TX_TYPE, dest, value, func);
        transaction = _signTransaction(transaction, userKey);

        // Act
        vm.prank(randomUser);
        minimalAccount.executeTransactionFromOutside(transaction);

        // Assert
        assertEq(mockERC20.balanceOf(address(minimalAccount)), mockERC20.AMOUNT());
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/
    function _getUnsignedTransaction(
        address from,
        uint8 transactionType,
        address to,
        uint256 value,
        bytes memory data
    )
        internal
        view
        returns (Transaction memory)
    {
        uint256 nonce = vm.getNonce(address(minimalAccount));
        bytes32[] memory emptyArray = new bytes32[](0);
        return Transaction({
            txType: transactionType,
            from: uint256(uint160(from)),
            to: uint256(uint160(to)),
            gasLimit: 1 << 24,
            gasPerPubdataByteLimit: 1 << 24,
            maxFeePerGas: 1 << 24,
            maxPriorityFeePerGas: 1 << 24,
            paymaster: 0,
            nonce: nonce,
            value: value,
            reserved: [uint256(0), uint256(0), uint256(0), uint256(0)],
            data: data,
            signature: hex"",
            factoryDeps: emptyArray,
            paymasterInput: hex"",
            reservedDynamic: hex""
        });
    }

    function _signTransaction(
        Transaction memory transaction,
        uint256 privateKey
    )
        public
        view
        returns (Transaction memory)
    {
        // This method returns the hash of the struct WITHOUT the signature.
        bytes32 unsignedTransactionHash = MemoryTransactionHelper.encodeHash(transaction);
        // I have no idea if this is correct to do this
        bytes32 digest = unsignedTransactionHash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        Transaction memory signedTransaction = transaction;
        signedTransaction.signature = abi.encodePacked(r, s, v); // Note the order!
        return signedTransaction;
    }
}
