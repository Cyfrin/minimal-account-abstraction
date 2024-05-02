// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IPaymasterFlow } from "@matterlabs/zksync-contracts/l2/system-contracts/interfaces/IPaymasterFlow.sol";
import { IContractDeployer } from "@matterlabs/zksync-contracts/l2/system-contracts/interfaces/IContractDeployer.sol";
import {
    ETH_TOKEN_SYSTEM_CONTRACT,
    BOOTLOADER_FORMAL_ADDRESS
} from "@matterlabs/zksync-contracts/l2/system-contracts/Constants.sol";
import { RLPEncoder } from "@matterlabs/zksync-contracts/l2/system-contracts/libraries/RLPEncoder.sol";
import { EfficientCall } from "@matterlabs/zksync-contracts/l2/system-contracts/libraries/EfficientCall.sol";
import {
    Transaction,
    LEGACY_TX_TYPE,
    EIP_712_TX_TYPE,
    EIP_1559_TX_TYPE,
    EIP_2930_TX_TYPE
} from "@matterlabs/zksync-contracts/l2/system-contracts/libraries/TransactionHelper.sol";

library MemoryTransactionHelper {
    using SafeERC20 for IERC20;

    /// @notice The EIP-712 typehash for the contract's domain
    bytes32 constant EIP712_DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId)");

    bytes32 constant EIP712_TRANSACTION_TYPE_HASH = keccak256(
        "Transaction(uint256 txType,uint256 from,uint256 to,uint256 gasLimit,uint256 gasPerPubdataByteLimit,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,uint256 paymaster,uint256 nonce,uint256 value,bytes data,bytes32[] factoryDeps,bytes paymasterInput)"
    );

    /// @notice Whether the token is Ethereum.
    /// @param _addr The address of the token
    /// @return `true` or `false` based on whether the token is Ether.
    /// @dev This method assumes that address is Ether either if the address is 0 (for convenience)
    /// or if the address is the address of the L2EthToken system contract.
    function isEthToken(uint256 _addr) internal pure returns (bool) {
        return _addr == uint256(uint160(address(ETH_TOKEN_SYSTEM_CONTRACT))) || _addr == 0;
    }

    /// @notice Calculate the suggested signed hash of the transaction,
    /// i.e. the hash that is signed by EOAs and is recommended to be signed by other accounts.
    function encodeHash(Transaction memory _transaction) internal view returns (bytes32 resultHash) {
        if (_transaction.txType == LEGACY_TX_TYPE) {
            resultHash = _encodeHashLegacyTransaction(_transaction);
        } else if (_transaction.txType == EIP_712_TX_TYPE) {
            resultHash = _encodeHashEIP712Transaction(_transaction);
        } else if (_transaction.txType == EIP_1559_TX_TYPE) {
            resultHash = _encodeHashEIP1559Transaction(_transaction);
        } else if (_transaction.txType == EIP_2930_TX_TYPE) {
            resultHash = _encodeHashEIP2930Transaction(_transaction);
        } else {
            // Currently no other transaction types are supported.
            // Any new transaction types will be processed in a similar manner.
            revert("Encoding unsupported tx");
        }
    }

    /// @notice Encode hash of the zkSync native transaction type.
    /// @return keccak256 hash of the EIP-712 encoded representation of transaction
    function _encodeHashEIP712Transaction(Transaction memory _transaction) private view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                EIP712_TRANSACTION_TYPE_HASH,
                _transaction.txType,
                _transaction.from,
                _transaction.to,
                _transaction.gasLimit,
                _transaction.gasPerPubdataByteLimit,
                _transaction.maxFeePerGas,
                _transaction.maxPriorityFeePerGas,
                _transaction.paymaster,
                _transaction.nonce,
                _transaction.value,
                // boo, less efficient cuz not calldata
                // EfficientCall.keccak(_transaction.data),
                keccak256(_transaction.data),
                keccak256(abi.encodePacked(_transaction.factoryDeps)),
                // EfficientCall.keccak(_transaction.paymasterInput)
                keccak256(_transaction.paymasterInput)
            )
        );

        bytes32 domainSeparator =
            keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256("zkSync"), keccak256("2"), block.chainid));

        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @notice Encode hash of the legacy transaction type.
    /// @return keccak256 of the serialized RLP encoded representation of transaction
    function _encodeHashLegacyTransaction(Transaction memory _transaction) private view returns (bytes32) {
        // Hash of legacy transactions are encoded as one of the:
        // - RLP(nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0)
        // - RLP(nonce, gasPrice, gasLimit, to, value, data)
        //
        // In this RLP encoding, only the first one above list appears, so we encode each element
        // inside list and then concatenate the length of all elements with them.

        bytes memory encodedNonce = RLPEncoder.encodeUint256(_transaction.nonce);
        // Encode `gasPrice` and `gasLimit` together to prevent "stack too deep error".
        bytes memory encodedGasParam;
        {
            bytes memory encodedGasPrice = RLPEncoder.encodeUint256(_transaction.maxFeePerGas);
            bytes memory encodedGasLimit = RLPEncoder.encodeUint256(_transaction.gasLimit);
            encodedGasParam = bytes.concat(encodedGasPrice, encodedGasLimit);
        }

        bytes memory encodedTo = RLPEncoder.encodeAddress(address(uint160(_transaction.to)));
        bytes memory encodedValue = RLPEncoder.encodeUint256(_transaction.value);
        // Encode only the length of the transaction data, and not the data itself,
        // so as not to copy to memory a potentially huge transaction data twice.
        bytes memory encodedDataLength;
        {
            // Safe cast, because the length of the transaction data can't be so large.
            uint64 txDataLen = uint64(_transaction.data.length);
            if (txDataLen != 1) {
                // If the length is not equal to one, then only using the length can it be encoded definitely.
                encodedDataLength = RLPEncoder.encodeNonSingleBytesLen(txDataLen);
            } else if (_transaction.data[0] >= 0x80) {
                // If input is a byte in [0x80, 0xff] range, RLP encoding will concatenates 0x81 with the byte.
                encodedDataLength = hex"81";
            }
            // Otherwise the length is not encoded at all.
        }

        // Encode `chainId` according to EIP-155, but only if the `chainId` is specified in the transaction.
        bytes memory encodedChainId;
        if (_transaction.reserved[0] != 0) {
            encodedChainId = bytes.concat(RLPEncoder.encodeUint256(block.chainid), hex"8080");
        }

        bytes memory encodedListLength;
        unchecked {
            uint256 listLength = encodedNonce.length + encodedGasParam.length + encodedTo.length + encodedValue.length
                + encodedDataLength.length + _transaction.data.length + encodedChainId.length;

            // Safe cast, because the length of the list can't be so large.
            encodedListLength = RLPEncoder.encodeListLen(uint64(listLength));
        }

        return keccak256(
            bytes.concat(
                encodedListLength,
                encodedNonce,
                encodedGasParam,
                encodedTo,
                encodedValue,
                encodedDataLength,
                _transaction.data,
                encodedChainId
            )
        );
    }

    /// @notice Encode hash of the EIP2930 transaction type.
    /// @return keccak256 of the serialized RLP encoded representation of transaction
    function _encodeHashEIP2930Transaction(Transaction memory _transaction) private view returns (bytes32) {
        // Hash of EIP2930 transactions is encoded the following way:
        // H(0x01 || RLP(chain_id, nonce, gas_price, gas_limit, destination, amount, data, access_list))
        //
        // Note, that on zkSync access lists are not supported and should always be empty.

        // Encode all fixed-length params to avoid "stack too deep error"
        bytes memory encodedFixedLengthParams;
        {
            bytes memory encodedChainId = RLPEncoder.encodeUint256(block.chainid);
            bytes memory encodedNonce = RLPEncoder.encodeUint256(_transaction.nonce);
            bytes memory encodedGasPrice = RLPEncoder.encodeUint256(_transaction.maxFeePerGas);
            bytes memory encodedGasLimit = RLPEncoder.encodeUint256(_transaction.gasLimit);
            bytes memory encodedTo = RLPEncoder.encodeAddress(address(uint160(_transaction.to)));
            bytes memory encodedValue = RLPEncoder.encodeUint256(_transaction.value);
            encodedFixedLengthParams =
                bytes.concat(encodedChainId, encodedNonce, encodedGasPrice, encodedGasLimit, encodedTo, encodedValue);
        }

        // Encode only the length of the transaction data, and not the data itself,
        // so as not to copy to memory a potentially huge transaction data twice.
        bytes memory encodedDataLength;
        {
            // Safe cast, because the length of the transaction data can't be so large.
            uint64 txDataLen = uint64(_transaction.data.length);
            if (txDataLen != 1) {
                // If the length is not equal to one, then only using the length can it be encoded definitely.
                encodedDataLength = RLPEncoder.encodeNonSingleBytesLen(txDataLen);
            } else if (_transaction.data[0] >= 0x80) {
                // If input is a byte in [0x80, 0xff] range, RLP encoding will concatenates 0x81 with the byte.
                encodedDataLength = hex"81";
            }
            // Otherwise the length is not encoded at all.
        }

        // On zkSync, access lists are always zero length (at least for now).
        bytes memory encodedAccessListLength = RLPEncoder.encodeListLen(0);

        bytes memory encodedListLength;
        unchecked {
            uint256 listLength = encodedFixedLengthParams.length + encodedDataLength.length + _transaction.data.length
                + encodedAccessListLength.length;

            // Safe cast, because the length of the list can't be so large.
            encodedListLength = RLPEncoder.encodeListLen(uint64(listLength));
        }

        return keccak256(
            bytes.concat(
                "\x01",
                encodedListLength,
                encodedFixedLengthParams,
                encodedDataLength,
                _transaction.data,
                encodedAccessListLength
            )
        );
    }

    /// @notice Encode hash of the EIP1559 transaction type.
    /// @return keccak256 of the serialized RLP encoded representation of transaction
    function _encodeHashEIP1559Transaction(Transaction memory _transaction) private view returns (bytes32) {
        // Hash of EIP1559 transactions is encoded the following way:
        // H(0x02 || RLP(chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, destination, amount,
        // data, access_list))
        //
        // Note, that on zkSync access lists are not supported and should always be empty.

        // Encode all fixed-length params to avoid "stack too deep error"
        bytes memory encodedFixedLengthParams;
        {
            bytes memory encodedChainId = RLPEncoder.encodeUint256(block.chainid);
            bytes memory encodedNonce = RLPEncoder.encodeUint256(_transaction.nonce);
            bytes memory encodedMaxPriorityFeePerGas = RLPEncoder.encodeUint256(_transaction.maxPriorityFeePerGas);
            bytes memory encodedMaxFeePerGas = RLPEncoder.encodeUint256(_transaction.maxFeePerGas);
            bytes memory encodedGasLimit = RLPEncoder.encodeUint256(_transaction.gasLimit);
            bytes memory encodedTo = RLPEncoder.encodeAddress(address(uint160(_transaction.to)));
            bytes memory encodedValue = RLPEncoder.encodeUint256(_transaction.value);
            encodedFixedLengthParams = bytes.concat(
                encodedChainId,
                encodedNonce,
                encodedMaxPriorityFeePerGas,
                encodedMaxFeePerGas,
                encodedGasLimit,
                encodedTo,
                encodedValue
            );
        }

        // Encode only the length of the transaction data, and not the data itself,
        // so as not to copy to memory a potentially huge transaction data twice.
        bytes memory encodedDataLength;
        {
            // Safe cast, because the length of the transaction data can't be so large.
            uint64 txDataLen = uint64(_transaction.data.length);
            if (txDataLen != 1) {
                // If the length is not equal to one, then only using the length can it be encoded definitely.
                encodedDataLength = RLPEncoder.encodeNonSingleBytesLen(txDataLen);
            } else if (_transaction.data[0] >= 0x80) {
                // If input is a byte in [0x80, 0xff] range, RLP encoding will concatenates 0x81 with the byte.
                encodedDataLength = hex"81";
            }
            // Otherwise the length is not encoded at all.
        }

        // On zkSync, access lists are always zero length (at least for now).
        bytes memory encodedAccessListLength = RLPEncoder.encodeListLen(0);

        bytes memory encodedListLength;
        unchecked {
            uint256 listLength = encodedFixedLengthParams.length + encodedDataLength.length + _transaction.data.length
                + encodedAccessListLength.length;

            // Safe cast, because the length of the list can't be so large.
            encodedListLength = RLPEncoder.encodeListLen(uint64(listLength));
        }

        return keccak256(
            bytes.concat(
                "\x02",
                encodedListLength,
                encodedFixedLengthParams,
                encodedDataLength,
                _transaction.data,
                encodedAccessListLength
            )
        );
    }

    /// @notice Processes the common paymaster flows, e.g. setting proper allowance
    /// for tokens, etc. For more information on the expected behavior, check out
    /// the "Paymaster flows" section in the documentation.
    function processPaymasterInput(Transaction memory _transaction) internal {
        require(_transaction.paymasterInput.length >= 4, "The standard paymaster input must be at least 4 bytes long");

        // bytes4 paymasterInputSelector = bytes4(_transaction.paymasterInput[0:4]);
        bytes4 paymasterInputSelector = bytes4(
            abi.encodePacked(
                _transaction.paymasterInput[0],
                _transaction.paymasterInput[1],
                _transaction.paymasterInput[2],
                _transaction.paymasterInput[3]
            )
        );
        if (paymasterInputSelector == IPaymasterFlow.approvalBased.selector) {
            require(
                _transaction.paymasterInput.length >= 68,
                "The approvalBased paymaster input must be at least 68 bytes long"
            );

            // While the actual data consists of address, uint256 and bytes data,
            // the data is needed only for the paymaster, so we ignore it here for the sake of optimization

            // damn, this isn't supported in solidity yet
            // https://github.com/ethereum/solidity/issues/14996
            // ready for this nonesense I'm about to do?
            bytes memory sliceData = abi.encodePacked(
                _transaction.paymasterInput[4],
                _transaction.paymasterInput[5],
                _transaction.paymasterInput[6],
                _transaction.paymasterInput[7],
                _transaction.paymasterInput[8],
                _transaction.paymasterInput[9],
                _transaction.paymasterInput[10],
                _transaction.paymasterInput[11],
                _transaction.paymasterInput[12],
                _transaction.paymasterInput[13],
                _transaction.paymasterInput[14],
                _transaction.paymasterInput[15],
                _transaction.paymasterInput[16],
                _transaction.paymasterInput[17],
                _transaction.paymasterInput[18],
                _transaction.paymasterInput[19],
                _transaction.paymasterInput[20],
                _transaction.paymasterInput[21],
                _transaction.paymasterInput[22],
                _transaction.paymasterInput[23],
                _transaction.paymasterInput[24],
                _transaction.paymasterInput[25],
                _transaction.paymasterInput[26],
                _transaction.paymasterInput[27],
                _transaction.paymasterInput[28],
                _transaction.paymasterInput[29],
                _transaction.paymasterInput[30],
                _transaction.paymasterInput[31],
                _transaction.paymasterInput[32],
                _transaction.paymasterInput[33],
                _transaction.paymasterInput[34],
                _transaction.paymasterInput[35],
                _transaction.paymasterInput[36],
                _transaction.paymasterInput[37],
                _transaction.paymasterInput[38],
                _transaction.paymasterInput[39],
                _transaction.paymasterInput[40],
                _transaction.paymasterInput[41],
                _transaction.paymasterInput[42],
                _transaction.paymasterInput[43],
                _transaction.paymasterInput[44],
                _transaction.paymasterInput[45],
                _transaction.paymasterInput[46],
                _transaction.paymasterInput[47],
                _transaction.paymasterInput[48],
                _transaction.paymasterInput[49],
                _transaction.paymasterInput[50],
                _transaction.paymasterInput[51],
                _transaction.paymasterInput[52],
                _transaction.paymasterInput[53],
                _transaction.paymasterInput[54],
                _transaction.paymasterInput[55],
                _transaction.paymasterInput[56],
                _transaction.paymasterInput[57],
                _transaction.paymasterInput[58],
                _transaction.paymasterInput[59],
                _transaction.paymasterInput[60],
                _transaction.paymasterInput[61],
                _transaction.paymasterInput[62],
                _transaction.paymasterInput[63],
                _transaction.paymasterInput[64],
                _transaction.paymasterInput[65],
                _transaction.paymasterInput[66],
                _transaction.paymasterInput[67],
                _transaction.paymasterInput[68]
            );
            (address token, uint256 minAllowance) = abi.decode(sliceData, (address, uint256));
            address paymaster = address(uint160(_transaction.paymaster));

            uint256 currentAllowance = IERC20(token).allowance(address(this), paymaster);
            if (currentAllowance < minAllowance) {
                // Some tokens, e.g. USDT require that the allowance is firsty set to zero
                // and only then updated to the new value.

                IERC20(token).safeIncreaseAllowance(paymaster, minAllowance);
            }
        } else if (paymasterInputSelector == IPaymasterFlow.general.selector) {
            // Do nothing. general(bytes) paymaster flow means that the paymaster must interpret these bytes on his own.
        } else {
            revert("Unsupported paymaster flow");
        }
    }

    /// @notice Pays the required fee for the transaction to the bootloader.
    /// @dev Currently it pays the maximum amount "_transaction.maxFeePerGas * _transaction.gasLimit",
    /// it will change in the future.
    function payToTheBootloader(Transaction memory _transaction) internal returns (bool success) {
        address bootloaderAddr = BOOTLOADER_FORMAL_ADDRESS;
        uint256 amount = _transaction.maxFeePerGas * _transaction.gasLimit;

        assembly {
            success := call(gas(), bootloaderAddr, amount, 0, 0, 0, 0)
        }
    }

    // Returns the balance required to process the transaction.
    function totalRequiredBalance(Transaction memory _transaction) internal pure returns (uint256 requiredBalance) {
        if (address(uint160(_transaction.paymaster)) != address(0)) {
            // Paymaster pays for the fee
            requiredBalance = _transaction.value;
        } else {
            // The user should have enough balance for both the fee and the value of the transaction
            requiredBalance = _transaction.maxFeePerGas * _transaction.gasLimit + _transaction.value;
        }
    }
}
