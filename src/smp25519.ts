/**
 * @module SMP25519
 * 
 * SMP25519 is designed to facilitate secure communication using the X25519 key exchange, BLAKE3 hashing, and
 * ChaCha20 encryption. It provides a straightforward interface for generating secure identities, creating handshake
 * messages, deriving shared secrets, and encrypting/decrypting data.
 */

import { x25519 } from "@noble/curves/ed25519";
import { blake3 } from "@noble/hashes/blake3";
import { chacha20 } from "@noble/ciphers/chacha";

const SMP25519_HANDSHAKE_REQUEST = new Uint8Array([0xff, 0x13]);
const SMP25519_HANDSHAKE_REQUEST_SIZE = SMP25519_HANDSHAKE_REQUEST.length;
const SMP25519_PRIVATE_KEY_SIZE = 32;
const SMP25519_PUBLIC_KEY_SIZE = 32;
const SMP25519_CHACHA20_KEY_SIZE = 32;
const SMP25519_CHACHA20_NONCE_SIZE = 12;
const SMP25519_SHARED_SECRET_SIZE = SMP25519_CHACHA20_KEY_SIZE + SMP25519_CHACHA20_NONCE_SIZE
const SMP25519_CONNECTION_ID_SIZE = 8

/**
 * Derives the public key from the given private key.
 *
 * @param privateKey - The private key as a 32-byte Uint8Array.
 * @returns The corresponding public key as a 32-byte Uint8Array.
 * @throws If the private key is not 32 bytes long.
 */
export function getPublicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
    if (privateKey.length != SMP25519_PRIVATE_KEY_SIZE)
        throw new Error(`Private key must be ${SMP25519_PRIVATE_KEY_SIZE} bytes long.`);

    return x25519.getPublicKey(privateKey);
}

/**
 * Generates a connection ID from the given public key using the BLAKE3 hash function.
 *
 * @param publicKey - The public key as a 32-byte Uint8Array.
 * @returns The connection ID as an 8-byte Uint8Array.
 * @throws If the public key is not 32 bytes long.
 */
export function generateConnectionIdFromPublicKey(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length != SMP25519_PUBLIC_KEY_SIZE)
        throw new Error(`Public key must be ${SMP25519_PUBLIC_KEY_SIZE} bytes long.`);

    return blake3(publicKey, { dkLen: SMP25519_CONNECTION_ID_SIZE });
}

/**
 * Represents an identity containing a private key, public key, and connection ID.
 */
export type Identity = {
    privateKey: Uint8Array,
    publicKey: Uint8Array,
    connectionId: Uint8Array
};

/**
 * Generates a unique identity consisting of a private key, public key, and connection ID.
 * 
 * The connection ID is generated from the public key and must not start with the predefined
    SMP25519_HANDSHAKE_REQUEST bytes.
 *
 * @returns A newly generated Identity object.
 */
export function generateIdentity(): Identity {
    while (true) {
        const privateKey = x25519.utils.randomPrivateKey();
        const publicKey = x25519.getPublicKey(privateKey);
        const connectionId = generateConnectionIdFromPublicKey(publicKey);

        if (connectionId.slice(0, SMP25519_HANDSHAKE_REQUEST_SIZE).every((val, index) => val !== SMP25519_HANDSHAKE_REQUEST[index]))
            return { privateKey,  publicKey, connectionId };
    }
}

/**
 * Creates a handshake message by prepending the SMP25519_HANDSHAKE_REQUEST to the public key.
 *
 * @param publicKey - The public key as a 32-byte Uint8Array.
 * @returns The handshake message as a Uint8Array.
 * @throws If the public key is not 32 bytes long.
 */
export function createHandshakeMessage(publicKey: Uint8Array): Uint8Array {
    if (publicKey.length != SMP25519_PUBLIC_KEY_SIZE)
        throw new Error(`Public key must be ${SMP25519_PUBLIC_KEY_SIZE} bytes long.`);

    const result = new Uint8Array(SMP25519_HANDSHAKE_REQUEST_SIZE + SMP25519_PUBLIC_KEY_SIZE);

    result.set(SMP25519_HANDSHAKE_REQUEST, 0);
    result.set(publicKey, SMP25519_HANDSHAKE_REQUEST_SIZE);

    return result;
}

/**
 * Checks if the given data is a valid handshake message.
 * 
 * A valid handshake message must start with the SMP25519_HANDSHAKE_REQUEST and contain a valid public key.
 *
 * @param data - The message to check.
 * @returns `true` if the message is a valid handshake message, otherwise `false`.
 */
export function isHandshakeMessage(data: Uint8Array): boolean {
    if (data.length < SMP25519_HANDSHAKE_REQUEST_SIZE + SMP25519_PUBLIC_KEY_SIZE)
        return false;

    if (data.slice(0, SMP25519_HANDSHAKE_REQUEST_SIZE).every((val, index) => val === SMP25519_HANDSHAKE_REQUEST[index]))
        return true;

    return false;
}

/**
 * Validates the given data based on its length.
 *
 * @param data - The data to validate.
 * @returns `true` if the data is valid, otherwise `false`.
 */
export function isValidData(data: Uint8Array): boolean {
    if (data.length > SMP25519_CONNECTION_ID_SIZE)
        return true;

    return false;
}

/**
 * Extracts the public key from a valid handshake message.
 *
 * @param handshake - The handshake message as a Uint8Array.
 * @returns The extracted public key as a 32-byte Uint8Array.
 * @throws If the handshake message is invalid.
 */
export function extractPublicKeyFromHandshake(handshake: Uint8Array): Uint8Array {
    if (isHandshakeMessage(handshake) !== true)
        throw new Error("Forgot to check for isHandshakeMessage.");

    return handshake.slice(SMP25519_HANDSHAKE_REQUEST_SIZE, SMP25519_HANDSHAKE_REQUEST_SIZE + SMP25519_PUBLIC_KEY_SIZE);
}

/**
 * Extracts the connection ID from the given data.
 *
 * @param data - The data containing the connection ID.
 * @returns The connection ID as an 8-byte Uint8Array.
 * @throws If the data does not contain a valid connection ID.
 */
export function extractConnectionIdFromData(data: Uint8Array): Uint8Array {
    if (data.length > SMP25519_CONNECTION_ID_SIZE)
        return data.slice(0, SMP25519_CONNECTION_ID_SIZE);
    
    throw new Error("Forgot to check for isHandshakeMessage.");
}

/**
 * Derives a shared secret using the provided private key and the public key received during the handshake.
 * 
 * This function uses the X25519 key exchange algorithm to compute a shared secret from the private key
 * and the public key. The resulting shared secret is then hashed using the BLAKE3 hashing function.
 *
 * @param privateKey - The private key as a 32-byte Uint8Array.
 * @param handshakePublicKey - The public key from the handshake as a 32-byte Uint8Array.
 * @param salt - An optional salt string.
 * @returns The derived shared secret as a Uint8Array.
 * @throws If the private key or handshake public key are not 32 bytes long.
 */
export function deriveSharedSecret(privateKey: Uint8Array, handshakePublicKey: Uint8Array, salt = ""): Uint8Array {
    if (privateKey.length != SMP25519_PRIVATE_KEY_SIZE)
        throw new Error(`Private key must be ${SMP25519_PRIVATE_KEY_SIZE} bytes long.`);

    if (handshakePublicKey.length != SMP25519_PUBLIC_KEY_SIZE)
        throw new Error(`Handshake public key must be ${SMP25519_PUBLIC_KEY_SIZE} bytes long.`);

    const sharedSecret = x25519.getSharedSecret(privateKey, handshakePublicKey);
    const smp25519String = new Uint8Array([0x53, 0x4d, 0x50, 0x32, 0x35, 0x35, 0x31, 0x39]); // SMP25519
    const utf8Encode = new TextEncoder();
    const saltArray = utf8Encode.encode(salt);

    const result = new Uint8Array(sharedSecret.length + smp25519String.length + saltArray.length);
    result.set(sharedSecret, 0);
    result.set(smp25519String, sharedSecret.length);
    if (saltArray.length > 0)
        result.set(saltArray, sharedSecret.length + smp25519String.length);

    return blake3(result, { dkLen: SMP25519_SHARED_SECRET_SIZE });
}

/**
 * Encrypts the given data using the shared secret and prepends the connection ID.
 *
 * @param connectionId - The connection ID as an 8-byte Uint8Array.
 * @param data - The data to encrypt as a Uint8Array.
 * @param sharedSecret - The shared secret as a Uint8Array.
 * @returns The encrypted message as a Uint8Array.
 * @throws If the connection ID, data, or shared secret are invalid.
 */
export function encryptAndSendData(connectionId: Uint8Array, data: Uint8Array, sharedSecret: Uint8Array): Uint8Array {
    if (connectionId.length != SMP25519_CONNECTION_ID_SIZE)
        throw new Error(`Connection id must be ${SMP25519_CONNECTION_ID_SIZE} bytes long.`);

    if (!(data.length > 0))
        throw new Error("You can't send nothing.");

    if (sharedSecret.length != SMP25519_SHARED_SECRET_SIZE)
        throw new Error(`Shared secret must be ${SMP25519_SHARED_SECRET_SIZE} bytes long.`);

    const key = sharedSecret.slice(0, SMP25519_CHACHA20_KEY_SIZE);
    const nonce = sharedSecret.slice(SMP25519_CHACHA20_KEY_SIZE, SMP25519_CHACHA20_KEY_SIZE + SMP25519_CHACHA20_NONCE_SIZE);

    const encryptedData = chacha20(key, nonce, data);

    const result = new Uint8Array(connectionId.length + encryptedData.length);
    result.set(connectionId, 0);
    result.set(encryptedData, connectionId.length);

    return result;
}

/**
 * Decrypts the received data using the provided shared secret.
 *
 * @param data - The received data as a Uint8Array.
 * @param sharedSecret - The shared secret as a Uint8Array.
 * @returns The decrypted data as a Uint8Array.
 * @throws If the data or shared secret are invalid.
 */
export function decryptReceivedData(data: Uint8Array, sharedSecret: Uint8Array): Uint8Array {
    if (!(data.length > SMP25519_CONNECTION_ID_SIZE))
        throw new Error("You can't receive nothing.");

    if (sharedSecret.length != SMP25519_SHARED_SECRET_SIZE)
        throw new Error(`Shared secret must be ${SMP25519_SHARED_SECRET_SIZE} bytes long.`);

    const key = sharedSecret.slice(0, SMP25519_CHACHA20_KEY_SIZE);
    const nonce = sharedSecret.slice(SMP25519_CHACHA20_KEY_SIZE, SMP25519_CHACHA20_KEY_SIZE + SMP25519_CHACHA20_NONCE_SIZE);

    const decryptedData = chacha20(key, nonce, data.slice(SMP25519_CONNECTION_ID_SIZE));

    return decryptedData;
}