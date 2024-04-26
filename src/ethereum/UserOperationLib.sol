// SPDX-License-Identifier: GPL-3.0
// Modified from: https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/UserOperationLib.sol
pragma solidity 0.8.24;

import {IPackedUserOperation} from "./interfaces/IPackedUserOperation.sol";
import {calldataKeccak, min} from "./Helpers.sol";

/**
 * Utility functions helpful when working with UserOperation structs.
 */
library UserOperationLib {
    uint256 public constant PAYMASTER_VALIDATION_GAS_OFFSET = 20;
    uint256 public constant PAYMASTER_POSTOP_GAS_OFFSET = 36;
    uint256 public constant PAYMASTER_DATA_OFFSET = 52;
    /**
     * Get sender from user operation data.
     * @param userOp - The user operation data.
     */

    function getSender(IPackedUserOperation.PackedUserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    /**
     * Relayer/block builder might submit the TX with higher priorityFee,
     * but the user should not pay above what he signed for.
     * @param userOp - The user operation data.
     */
    function gasPrice(IPackedUserOperation.PackedUserOperation calldata userOp) internal view returns (uint256) {
        unchecked {
            (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = unpackUints(userOp.gasFees);
            if (maxFeePerGas == maxPriorityFeePerGas) {
                //legacy mode (for networks that don't support basefee opcode)
                return maxFeePerGas;
            }
            return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }
    }

    /**
     * Pack the user operation data into bytes for hashing.
     * @param userOp - The user operation data.
     */
    function encode(IPackedUserOperation.PackedUserOperation calldata userOp)
        internal
        pure
        returns (bytes memory ret)
    {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        bytes32 accountGasLimits = userOp.accountGasLimits;
        uint256 preVerificationGas = userOp.preVerificationGas;
        bytes32 gasFees = userOp.gasFees;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

        return abi.encode(
            sender,
            nonce,
            hashInitCode,
            hashCallData,
            accountGasLimits,
            preVerificationGas,
            gasFees,
            hashPaymasterAndData
        );
    }

    function unpackUints(bytes32 packed) internal pure returns (uint256 high128, uint256 low128) {
        return (uint128(bytes16(packed)), uint128(uint256(packed)));
    }

    //unpack just the high 128-bits from a packed value
    function unpackHigh128(bytes32 packed) internal pure returns (uint256) {
        return uint256(packed) >> 128;
    }

    // unpack just the low 128-bits from a packed value
    function unpackLow128(bytes32 packed) internal pure returns (uint256) {
        return uint128(uint256(packed));
    }

    function unpackMaxPriorityFeePerGas(IPackedUserOperation.PackedUserOperation calldata userOp)
        internal
        pure
        returns (uint256)
    {
        return unpackHigh128(userOp.gasFees);
    }

    function unpackMaxFeePerGas(IPackedUserOperation.PackedUserOperation calldata userOp)
        internal
        pure
        returns (uint256)
    {
        return unpackLow128(userOp.gasFees);
    }

    function unpackVerificationGasLimit(IPackedUserOperation.PackedUserOperation calldata userOp)
        internal
        pure
        returns (uint256)
    {
        return unpackHigh128(userOp.accountGasLimits);
    }

    function unpackCallGasLimit(IPackedUserOperation.PackedUserOperation calldata userOp)
        internal
        pure
        returns (uint256)
    {
        return unpackLow128(userOp.accountGasLimits);
    }

    function unpackPaymasterVerificationGasLimit(IPackedUserOperation.PackedUserOperation calldata userOp)
        internal
        pure
        returns (uint256)
    {
        return uint128(bytes16(userOp.paymasterAndData[PAYMASTER_VALIDATION_GAS_OFFSET:PAYMASTER_POSTOP_GAS_OFFSET]));
    }

    function unpackPostOpGasLimit(IPackedUserOperation.PackedUserOperation calldata userOp)
        internal
        pure
        returns (uint256)
    {
        return uint128(bytes16(userOp.paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET:PAYMASTER_DATA_OFFSET]));
    }

    function unpackPaymasterStaticFields(bytes calldata paymasterAndData)
        internal
        pure
        returns (address paymaster, uint256 validationGasLimit, uint256 postOpGasLimit)
    {
        return (
            address(bytes20(paymasterAndData[:PAYMASTER_VALIDATION_GAS_OFFSET])),
            uint128(bytes16(paymasterAndData[PAYMASTER_VALIDATION_GAS_OFFSET:PAYMASTER_POSTOP_GAS_OFFSET])),
            uint128(bytes16(paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET:PAYMASTER_DATA_OFFSET]))
        );
    }

    /**
     * Hash the user operation data.
     * @param userOp - The user operation data.
     */
    function hash(IPackedUserOperation.PackedUserOperation calldata userOp) internal pure returns (bytes32) {
        return keccak256(encode(userOp));
    }
}
