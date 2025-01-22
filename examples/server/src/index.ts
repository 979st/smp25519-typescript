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
 * Secure UDP server example using the smp25519 package.
 * This script demonstrates how to establish a secure communication channel with a single
 * client at a time using key exchange and encryption.
 */
function main() {
    // Step 1: Generate the server's identity.
    // const { privateKey, publicKey, connectionId } = smp25519.generateIdentity();

    // Or use a pre-existing private key (Base64 encoded) and derive the public key.
    const privateKey = base64.toUint8Array("4Pe2QvF6zk41OWkMTqVR8e9nvwhbOEaDRti6oykaG18=");
    const publicKey = smp25519.getPublicKeyFromPrivate(privateKey);
    console.log(`Server public key (Base64): ${base64.fromUint8Array(publicKey)}`);

    // Step 2: Set up the UDP socket.
    const socket = dgram.createSocket("udp4");
    const SERVER_PORT = 12000;

    console.log(`Secure UDP Server: Listening on port ${SERVER_PORT}`);

    // Variables to store client-specific connection data.
    let clientConnectionId: Uint8Array;
    let clientSharedSecret: Uint8Array;

    // Step 3: Main server loop.
    socket.on("message", (msg, rinfo) => {
        // Step 4: Handle handshake messages.
        if (smp25519.isHandshakeMessage(msg) == true) {
            console.log(`Handshake received from ${rinfo.address}:${rinfo.port}`);

            // Extract the client's public key and generate a connection ID.
            const clientPublicKey = smp25519.extractPublicKeyFromHandshake(msg);
            clientConnectionId = smp25519.generateConnectionIdFromPublicKey(clientPublicKey);

            // Derive a shared secret using the client's public key and a salt.
            // clientSharedSecret = smp25519.deriveSharedSecret(privateKey, clientPublicKey, "examplesalt");
            clientSharedSecret = smp25519.deriveSharedSecret(privateKey, clientPublicKey);

            // Respond with the server's handshake message.
            socket.send(smp25519.createHandshakeMessage(publicKey), rinfo.port, rinfo.address, (err) => {
                if (err) {
                    console.error(`Error: Unable to send handshake message for reason: ${err}`)
                    exit(-1);
                }
            });

            return;
        }

        // Step 5: Handle encrypted messages.
        if (smp25519.isValidData(msg) == true && clientSharedSecret.length > 0) {
            // Verify the connection ID matches the client.
            if (smp25519.extractConnectionIdFromData(msg).every((val, index) => val !== clientConnectionId[index])) {
                console.log(`Notice: Unknown client ID from ${rinfo.address}:${rinfo.port}. Ignoring message.`);
                return;
            }

            // Decrypt the received message.
            const decryptedMessage = smp25519.decryptReceivedData(msg, clientSharedSecret);
            console.log(`Message from ${rinfo.address}:${rinfo.port}: ${uint8ArrayToString(decryptedMessage)}`);

            // Send an encrypted response back to the client.
            const responseMessage = "Hello from Server!";
            const encryptedMessage = smp25519.encryptAndSendData(clientConnectionId, stringToUint8Array(responseMessage), clientSharedSecret);
            socket.send(encryptedMessage, rinfo.port, rinfo.address, (err) => {
                if (err) {
                    console.error(`Error: Unable to send handshake message for reason: ${err}`)
                    exit(-1);
                }
            });
            console.log("Response sent.");

            return;
        }

        // Step 6: Handle unrecognized data.
        console.log(`Notice: Received unknown data from ${rinfo.address}:${rinfo.port}`);
    });

    // Bind to port
    socket.bind(SERVER_PORT);
}

main();