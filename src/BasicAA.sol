

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24; 

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";  
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol"; 
import {INonceManager} from "lib/account-abstraction/contracts/interfaces/INonceManager.sol"; 
import {SIG_VALIDATION_SUCCESS, SIG_VALIDATION_FAILED} from "lib/account-abstraction/contracts/core/Helpers.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol"; 
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol"; 
import {MessageHashUtils} from "@openzeppelin/contracts/utils/MessagehashUtils.sol";  


/// @title BasicAA 
/// @notice A basic account abstraction contract compliant with ERC-4337 standard
/// @dev This contract is meant to be used as a base contract for more complex account abstraction contracts - it implements the IAccount interface and inherits from Ownable for access control . 
/// @dev we enhance this smart account by including 'getnonce' method to get the nonce of the account and 'getEntryPoint' method to get the address of the entryPoint contract.

contract BasicAA  is IAccount,Ownable, INonceManager {

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Custom error thrown when a function is called by an address other than the EntryPoints contract
    error BasicAA__NotEntryPointContract();
    /// @notice Custom error thrown when a function is called by an address other than the EntryPoints contract or the owner
    error BasicAA__NotFromEntryPointOrOwner();
    /// @notice Custom error thrown whhen an external call fails during execution
    error BasicAA__ExternalCallFailed(bytes result);
    
    

    /*//////////////////////////////////////////////////////////////
                             STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Address of the EntryPoints contract
    IEntryPoint private immutable i_entryPoint; 
    /// @notice Mapping of nonces for each account
    mapping(address => mapping(uint192 => uint256)) private nonces;

    /// @notice Ensures the function is only callable by the EntryPoints contract
    modifier onlyEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert BasicAA__NotEntryPointContract();
        }
        _;
    }

    
    
    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/    
    
    // @notice Ensures the function is only callable by the EntryPoints contract or the owner
    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert BasicAA__NotFromEntryPointOrOwner();
        }
        _;
    }



    /*//////////////////////////////////////////////////////////////
                                FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    constructor(address _entryPoint) Ownable(msg.sender) { 
        i_entryPoint = IEntryPoint(_entryPoint);
    }

    /// @notice Fallback function to allow the contract to receive Ether
    receive() external payable {}




    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Executes a transaction on behalf of the account
    /// @dev Can only be called by the EntryPoints contract or the owner
    /// @param dest The destination address for the transaction
    /// @param value The amount of Ether to send with the transaction
    /// @param functionData The calldata to send with the transaction

    function execute(address dest, uint256 value, bytes calldata functionData) 
    external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(functionData);
        if (!success) {
            revert BasicAA__ExternalCallFailed(result);
        }
    }



    /// @notice Validates the user operation and pays the fees to the EntryPoint contract 
    /// @dev This function is designed to be callable from outside the contract (by the entryPoint contract
    /// @dev and only by it (thus the 'require' statement in the modifier) . 
    /// @dev **override** : This function is meant to implemetn the interface method.
    /// @param userOp The user operation to validate 
    /// @param userOpHash The hash of the user operation 
    /// @param missingAccountFunds The missing funds to be paid by the account to execute the transaction 
    
    function validateUserOp(PackedUserOperation calldata userOp), bytes32 userOpHash, uint256 missingAccountFunds) 
    external override require FromEntryPoint returns (uint256 validationData) {
        uint192 nonceKey = uint192(bytes20(address.this)); 
        uint256 nonce = getNonce(msg.sender, nonceKey); 
        if(userOpNonce != nonce) {
            return SIG_VALIDATION_FAILED;
        } 
               validationData = _validatesignature(userOp, userOpHash);
               if (validationData == SIG_VALIDATION_SUCCESS) {
                  _payPrefund(missingAccountFunds);
                  ///@dev Incrementing the nonce of the account after succesful validation of the userOperation
                    nonces[msg.sender][nonceKey] = nonce + 1; 
        }
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice This function is here to make sure the signer of a userOperation is who it is supposed to be,
    /// @notice whether the signature is validated via a google session key or via a signature aggregator.
    /// @dev uses EIP 191 signautre standard 
    /// @param userOp The userOperation to validate
    /// @param userOpHash The hash of the userOperation 
    /// @return validationData A packed value indicating signature validity and the signer's address
    function _validatesignature(PackedUserOperation calldata userOp, bytes32 userOpHash) 
    internal view returns (uint256 validationData) 
    {
        /// @dev we use OpenZeppelin cryptography libraries methods to abstract awya the complexity of signature validation with eip 191 standard.
        bytes32 ethsignedMessageHash = MessagehashUtils.toEthsigned messageHash(userOpHash);
        address signer = ECDSA.recover(ethsignedMessageHash, userOp.signature); 
        if (signer != owner()) { 
            // using a Helper contract to validate the signature
            return SIG_VALIDATIOP_FAILED; 
        } return SIG_VALIDATION_SUCCESS; 
    }




    /// @notice This function is here to prepay funds to the EntryPoint contract the amount that is necessary to execute the transaction.
    /// @param missingAccountFunds The amount of funds missing in the account to execute the transaction and to pay the EntryPoint contract.
    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds  != 0) {
            (bool success, ) = payable(msg.sender).call{
                value: missingAccountFunds,
                gas: type(uint256).max}
                (""); 
            (success); 
            
        }
    }




    /*//////////////////////////////////////////////////////////////
                            GETTERS FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the address of the EntryPoints contract
    /// @return The address of the EntryPoints contract

    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }

    /// @notice Returns the nonce of the account
    /// @param sender The address of the account
    /// @param key The key of the account 
    
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce) {
        return nonces[sender][key];  
    }
}