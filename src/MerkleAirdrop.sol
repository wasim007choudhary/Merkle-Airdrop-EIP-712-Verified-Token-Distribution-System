// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/*//////////////////////////////////////////////////////////////
                            IMPORTS
//////////////////////////////////////////////////////////////*/
import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title MerkleAirdrop
 * @author Wasim Choudhary
 * @notice This contract enables eligible users to claim ERC20 token airdrops
 * by providing a valid Merkle proof and an EIP-712 signature for verification.
 * @dev
 * - Uses Merkle proofs to verify inclusion of a user's claim in the airdrop tree.
 * - Uses EIP-712 typed data signatures to confirm that the claim was authorized
 *   by the rightful account holder (off-chain signed message).
 * - Tracks claims on-chain to prevent double-claiming.
 *
 * The default token used here is FPToken, but any ERC20-compliant token can be supported.
 */

/*//////////////////////////////////////////////////////////////
                        |  CONTRACT
//////////////////////////////////////////////////////////////*/
contract MerkleAirdrop is EIP712 {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/
    /// @notice Thrown when the EIP712 signature is invalid.
    error MerkleAirdrop___claim__AccountAddressHasAlreadyClaimed();

    /// @notice Thrown when the EIP712 signature is invalid.
    error MerkleAirdrop___claim__InvalidSignature();

    /// @notice Thrown when the Merkle proof is invalid.
    error MerkleAirdrop___claim__InvalidProof();

    /*//////////////////////////////////////////////////////////////
                             STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    /// @notice Root of the Merkle tree that defines claim eligibility.
    bytes32 private immutable i_merkleRoot;

    /// @notice ERC20 token being distributed.
    IERC20 private immutable i_airdropToken;

    /// @notice Mapping to track whether an address has already claimed.
    mapping(address => bool) private s_hasClaimed;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/
    /**
     *  @notice Struct representing claim data.
     *  @param accountAddress The address of the eligible claimer.
     *  @param claimAmount The amount of tokens claimable.
     */
    struct ClaimAirdrop {
        address accountAddress;
        uint256 claimAmount;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/
    /// @notice EIP712 typehash used for hashing structured claim data.
    bytes32 private constant MESSAGE_TYPEHASH = keccak256("ClaimAirdrop(address accountAddress,uint256 claimAmount)");

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Emitted when a user successfully claims their airdrop.
     * @param accountAddress The address that received the tokens.
     * @param claimableAmount The amount of tokens claimed.
     */
    event AirdropClaimed(address indexed accountAddress, uint256 claimableAmount);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    /// @param merkleRoot The root hash of the Merkle tree containing valid claimers.
    /// @param airdropToken The ERC20 token(which in this case is the FPToken) address to distribute.
    constructor(bytes32 merkleRoot, IERC20 airdropToken) EIP712("MerkleAirdrop", "1") {
        i_merkleRoot = merkleRoot;
        i_airdropToken = airdropToken;
    }

    /*//////////////////////////////////////////////////////////////
                              EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Allows an eligible user to claim their allocated ERC20 tokens from the airdrop.
     * @dev
     * This function verifies two layers of proof before releasing tokens:
     *
     * 1. **Merkle Proof Verification** — Confirms that the user's address and claim amount
     *    exist within the predefined Merkle root (i.e., the official list of eligible claimers).
     *
     * 2. **EIP-712 Signature Verification** — Ensures the claim was cryptographically authorized
     *    by the account holder off-chain, preventing anyone else from claiming on their behalf.
     *
     * Once both proofs are valid, the function transfers the tokens to the claimer and
     * records that the address has claimed to prevent double-claiming.
     *
     * @param accountAddress The address of the claimer (the account eligible to receive tokens).
     * @param amountToClaim The exact amount of tokens being claimed.
     * @param merkleProof The Merkle proof proving inclusion of this claim within the Merkle tree root.
     * @param v The recovery byte of the ECDSA signature (27 or 28).
     *          It helps determine which of the two possible public keys corresponds
     *          to the private key that signed the message.
     * @param r The first 32-byte component of the ECDSA signature (elliptic-curve output).
     * @param s The second 32-byte component of the ECDSA signature (elliptic-curve output).
     */
    function claim(
        address accountAddress,
        uint256 amountToClaim,
        bytes32[] calldata merkleProof,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (s_hasClaimed[accountAddress]) {
            revert MerkleAirdrop___claim__AccountAddressHasAlreadyClaimed();
        }

        if (!_isValidSignature(accountAddress, getMessageHash(accountAddress, amountToClaim), v, r, s)) {
            revert MerkleAirdrop___claim__InvalidSignature();
        }

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(accountAddress, amountToClaim))));
        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert MerkleAirdrop___claim__InvalidProof();
        }

        s_hasClaimed[accountAddress] = true;

        emit AirdropClaimed(accountAddress, amountToClaim);
        i_airdropToken.safeTransfer(accountAddress, amountToClaim);
    }

    /// @notice Returns the Merkle root hash.
    function getMerkleRoot() external view returns (bytes32) {
        return i_merkleRoot;
    }

    /// @notice Returns the ERC20 token being distributed.We are using FPToken. This contract can be used to any ERC20s for Airdrop
    function getAirdropToken() external view returns (IERC20) {
        return i_airdropToken;
    }

    /*//////////////////////////////////////////////////////////////
                              PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Generates the EIP-712 compliant hash (typed data digest) that must be signed by the eligible claimer or used for signature verification.
     * @dev This hash represents the structured claim data encoded as per EIP-712, combining the predefined typehash and the provided claim details.
     * It is used to confirm that a claim signature was produced by the intended account.
     * @param accountInfo The address of the account eligible to claim tokens.
     * @param amountInfo The specific token amount being claimed.
     * @return digest The EIP-712 encoded message hash ready for signing or verification.
     */

    function getMessageHash(address accountInfo, uint256 amountInfo) public view returns (bytes32 digest) {
        digest = _hashTypedDataV4(
            keccak256(
                abi.encode(MESSAGE_TYPEHASH, ClaimAirdrop({accountAddress: accountInfo, claimAmount: amountInfo}))
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                             INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Verifies whether a given ECDSA signature truly comes from the expected account.
     * @dev
     * Every digital signature is like a cryptographic “proof of authorship.”
     * This function checks that proof by using the EIP-712 message hash (digest)
     * and the `(v, r, s)` signature values to recover the signer’s address.
     *
     * Here’s how it works conceptually:
     * - When someone signs data off-chain (like in MetaMask), the wallet uses their **private key**
     *   to produce a unique signature that can only be made by that account.
     * - Anyone (including this contract) can later verify that signature by using only the **public key**
     *   — without ever seeing or needing the private key.
     * - The verification is done by **recovering** the signer’s address from the signature.
     * - If the recovered address equals the one claimed (`accountAddress`),
     *   the signature is proven valid.
     *
     * In simpler terms:
     * 🧠 The contract is asking, “Can I mathematically confirm that this signature really came
     * from the person who owns `accountAddress`, and that they approved this exact message?”
     *
     * @param accountAddress The Ethereum address expected to have signed the message (the claimed signer).
     * @param digest The EIP-712 formatted message hash — the exact data that was signed off-chain.
     * @param v The recovery byte of the signature (used to select the correct public key, typically 27 or 28).
     * @param r The first 32-byte component of the signature (part of the elliptic curve output).
     * @param s The second 32-byte component of the signature (part of the elliptic curve output).
     * @return isValid True if the recovered signer’s address matches `accountAddress`, false otherwise.
     */

    function _isValidSignature(address accountAddress, bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        internal
        pure
        returns (bool)
    {
        (address actualSigner, ECDSA.RecoverError recErr,) = ECDSA.tryRecover(digest, v, r, s);
        if (recErr != ECDSA.RecoverError.NoError) {
            return false;
        }
        if (actualSigner == address(0) || actualSigner != accountAddress) {
            return false;
        }
        return (actualSigner == accountAddress);
    }
}

