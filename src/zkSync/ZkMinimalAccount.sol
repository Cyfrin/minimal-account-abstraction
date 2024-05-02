// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// zkSync imports
import {
    IAccount,
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "@matterlabs/zksync-contracts/l2/system-contracts/interfaces/IAccount.sol";
import {
    Transaction,
    TransactionHelper
} from "@matterlabs/zksync-contracts/l2/system-contracts/libraries/TransactionHelper.sol";
import {
    BOOTLOADER_FORMAL_ADDRESS,
    NONCE_HOLDER_SYSTEM_CONTRACT,
    DEPLOYER_SYSTEM_CONTRACT
} from "@matterlabs/zksync-contracts/l2/system-contracts/Constants.sol";
import { SystemContractsCaller } from
    "@matterlabs/zksync-contracts/l2/system-contracts/libraries/SystemContractsCaller.sol";
import { INonceHolder } from "@matterlabs/zksync-contracts/l2/system-contracts/interfaces/INonceHolder.sol";
import { Utils } from "@matterlabs/zksync-contracts/l2/system-contracts/libraries/Utils.sol";
import { SystemContractHelper } from
    "@matterlabs/zksync-contracts/l2/system-contracts/libraries/SystemContractHelper.sol";

// OZ Imports
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract ZkMinimalAccount is Ownable, IAccount {
    using TransactionHelper for Transaction;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/
    error ZkMinimalAccount__OnlyBootloader();
    error ZkMinimalAccount__FailedToPay();
    error ZkMinimalAccount__InvalidSignature();
    error ZkMinimalAccount__ExecutionFailed();
    error ZkMinimalAccount__NotFromBootloaderOrOwner();

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/
    modifier onlyBootloader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkMinimalAccount__OnlyBootloader();
        }
        _;
    }

    modifier requireFromBootloaderOrOwner() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != owner()) {
            revert ZkMinimalAccount__NotFromBootloaderOrOwner();
        }
        _;
    }

    // /**
    //  * @dev Simulate the behavior of the EOA if it is called via `delegatecall`.
    //  * Thus, the default account on a delegate call behaves the same as EOA on Ethereum.
    //  * If all functions will use this modifier AND the contract will implement an empty payable fallback()
    //  * then the contract will be indistinguishable from the EOA when called.
    //  */
    // modifier ignoreInDelegateCall() {
    //     address codeAddress = SystemContractHelper.getCodeAddress();
    //     if (codeAddress != address(this)) {
    //         // If the function was delegate called, behave like an EOA.
    //         assembly {
    //             return(0, 0)
    //         }
    //     }

    //     // Continue execution if not delegate called.
    //     _;
    // }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    constructor() Ownable(msg.sender) { }

    function validateTransaction(
        bytes32, /*txHash*/
        bytes32 suggestedSignedHash,
        Transaction calldata transaction
    )
        external
        payable
        onlyBootloader
        returns (bytes4 magic)
    {
        magic = _validateTransaction(suggestedSignedHash, transaction);
    }

    function executeTransaction(
        bytes32, /*txHash*/
        bytes32, /*suggestedSignedHash*/
        Transaction calldata transaction
    )
        external
        payable
        // ignoreInDelegateCall
        requireFromBootloaderOrOwner
    {
        _executeTransaction(transaction);
    }

    // There is no point in providing possible signed hash in the `executeTransactionFromOutside` method,
    // since it typically should not be trusted.
    function executeTransactionFromOutside(Transaction calldata transaction) external payable {
        _validateTransaction(bytes32(0), transaction);
        _executeTransaction(transaction);
    }

    function payForTransaction(
        bytes32, /*_txHash*/
        bytes32, /*_suggestedSignedHash*/
        Transaction calldata _transaction
    )
        external
        payable
    {
        bool success = _transaction.payToTheBootloader();
        if (!success) {
            revert ZkMinimalAccount__FailedToPay();
        }
    }

    function prepareForPaymaster(
        bytes32, /*_txHash*/
        bytes32, /*_possibleSignedHash*/
        Transaction calldata _transaction
    )
        external
        payable
    {
        _transaction.processPaymasterInput();
    }

    /*//////////////////////////////////////////////////////////////
                          FUNCTIONS - INTERNAL
    //////////////////////////////////////////////////////////////*/
    function _validateTransaction(
        bytes32, /*suggestedSignedHash*/
        Transaction calldata transaction
    )
        internal
        returns (bytes4 magic)
    {
        // Increment nonce, ignore return data
        _incrementNonce(transaction.nonce);

        // Check for fee to pay
        uint256 totalRequiredBalance = transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert ZkMinimalAccount__FailedToPay();
        }

        // Check signature
        bytes32 txHash = transaction.encodeHash(); // This removes the signature from the struct, then hashes it
        bool validSignature = _isValidSignature(transaction.signature, txHash);
        if (validSignature) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }
        return magic;
    }

    function _executeTransaction(Transaction calldata transaction) internal {
        address to = address(uint160(transaction.to));
        uint128 value = Utils.safeCastToU128(transaction.value);
        bytes memory data = transaction.data;

        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gas = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(gas, to, value, data);
        } else {
            bool success;
            assembly {
                success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            }
            if (!success) {
                revert ZkMinimalAccount__ExecutionFailed();
            }
        }
    }

    function _incrementNonce(uint256 nonce) internal returns (bytes memory) {
        return SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (nonce))
        );
    }

    /*//////////////////////////////////////////////////////////////
                             VIEW AND PURE
    //////////////////////////////////////////////////////////////*/
    function _isValidSignature(bytes calldata signature, bytes32 transactionHash) internal view returns (bool) {
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(transactionHash);
        if (owner() != ECDSA.recover(hash, signature)) {
            return false;
        }
        return true;
    }
}
