// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";
import {
    MemoryTransactionHelper,
    Transaction,
    EIP_1559_TX_TYPE
} from "lib/mock-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract DefaultAccountTest is Test {
    using MessageHashUtils for bytes32;
    using MemoryTransactionHelper for Transaction;

    DefaultAccount defaultAccount;
    MockERC20 mockERC20;
    address user;
    uint256 userKey;
    address payable randomUser;

    bytes32 constant EMPTY_BYTES32 = bytes32(0);
    uint8 constant ZKSYNC_AA_TX_TYPE = 0x71;

    function setUp() public {
        mockERC20 = new MockERC20();
        // Every account in zkSync is technically a smart contract account!
        (user, userKey) = makeAddrAndKey("user");
        randomUser = payable(makeAddr("randomUser"));
    }

    function testDefaultAccountCanExecuteCommands() public {
        // Arrange
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory func = abi.encodeWithSelector(MockERC20.mint.selector);

        // Signature doesn't matter since it's the owner calling
        Transaction memory transaction = _getUnsignedTransaction(user, EIP_1559_TX_TYPE, dest, value, func);

        // Act
        // if this passes, it should just return 0,0
        // wtf, how do i check for this????
        vm.prank(randomUser);
        defaultAccount.executeTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);

        // Assert
        assertEq(mockERC20.balanceOf(address(defaultAccount)), mockERC20.AMOUNT());
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS (redundant)
    //////////////////////////////////////////////////////////////*/
    function _getUnsignedTransaction(
        address from,
        uint8 transactionType,
        address to,
        uint256 value,
        bytes memory data
    )
        internal
        pure
        returns (Transaction memory)
    {
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
            nonce: 0, // hard coded for 0 for now
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
