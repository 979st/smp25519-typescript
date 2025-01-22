import * as smp25519 from "smp25519";
import dgram from "dgram";
import { exit } from "process";
import * as base64 from "js-base64"

function stringToUint8Array(input: string): Uint8Array {
    const encoder = new TextEncoder();
    return encoder.encode(input);
}

function uint8ArrayToString(input: Uint8Array): string {
    const decoder = new TextDecoder();
    return decoder.decode(input);
}

/*
 * Secure UDP client example using the smp25519 package.
 * This script demonstrates how to establish a secure communication channel with a server using key exchange and encryption.
 */
function main() {
    // Step 1: Generate client identity (private key, public key, and connection ID).
    const { privateKey, publicKey, connectionId } = smp25519.generateIdentity();

    // Step 2 (RECOMMENDED): Define the server's known public key (Base64 encoded).
    let knownServerPublicKey = base64.toUint8Array("Vh4DBTYyDbwTqg1eZzTnuTxThscIoNQgLpxgsBCOFCU=");

    // Step 3: Create a UDP socket.
    const socket = dgram.createSocket("udp4");
    const SERVER_HOST = "localhost";
    const SERVER_PORT = 12000;

    console.log(`Secure UDP Client: Attempting connection to ${SERVER_HOST}:${SERVER_PORT}.`);

	// Variables to store server-specific connection data.
    let serverPublicKey: Uint8Array;
    let sharedSecret: Uint8Array;

    // Message handler
    socket.on("message", (msg, rinfo) => {
        // Step 5: Receive and validate handshake response from the server.
        if (smp25519.isHandshakeMessage(msg) == true) {
            // Extract the server's public key from the handshake message.
            serverPublicKey = smp25519.extractPublicKeyFromHandshake(msg);

            // (RECOMMENDED) Verify the server's public key.
            if (serverPublicKey.every((val, index) => val !== knownServerPublicKey[index])) {
                console.error("Error: Known server public key mismatch. Aborting connection.");
                exit(-1);
            }

            // Step 6: Derive the shared secret using the server's public key and a salt.
            // sharedSecret = smp25519.deriveSharedSecret(privateKey, serverPublicKey, "examplesalt");
            sharedSecret = smp25519.deriveSharedSecret(privateKey, serverPublicKey);

            // Send something.
            socket.send(smp25519.encryptAndSendData(connectionId, stringToUint8Array("Hello from Client!"), sharedSecret), SERVER_PORT, SERVER_HOST, (err) => {
                if (err) {
                    console.error(`Error: Unable to send message for reason: ${err}`)
                    exit(-1);
                }
            });

            return;
        }

        // Receive and decrypt the server's response.
        if (smp25519.isValidData(msg) == true && sharedSecret.length > 0) {
            const decryptedMessage = smp25519.decryptReceivedData(msg, sharedSecret);
            console.log(`Server response from ${rinfo.address}:${rinfo.port}: ${uint8ArrayToString(decryptedMessage)}`);

            return;
        }

        console.error(`Error: Unknown message from ${rinfo.address}:${rinfo.port}`)
        exit(-1);
    });

    // Step 4: Send handshake message containing the client's public key.
    socket.send(smp25519.createHandshakeMessage(publicKey), SERVER_PORT, SERVER_HOST, (err) => {
        if (err) {
            console.error(`Error: Unable to send handshake message for reason: ${err}`)
            exit(-1);
        }
    });
}

main();