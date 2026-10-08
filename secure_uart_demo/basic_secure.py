import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


key = ChaCha20Poly1305.generate_key()
cipher = ChaCha20Poly1305(key)
seq = 0


def send(message):
    global seq
    seq += 1
    nonce = struct.pack(">Q", seq) + b"\x00\x00\x00\x00"
    ciphertext = cipher.encrypt(nonce, message.encode(), None)
    packet = nonce + ciphertext
    return packet


def receive(packet):
    nonce = packet[:12]
    ciphertext = packet[12:]
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except InvalidTag:
        return None


print("Secure message demo (type 'quit' to exit)")
print("-" * 40)

while True:
    message = input("\nEnter a message: ")
    if message.lower() == "quit":
        break

    packet = send(message)
    print("Encrypted packet :", packet.hex())

    result = receive(packet)
    if result is None:
        print("Result           : REJECTED (tampered or wrong key)")
    else:
        print("Decrypted message:", result)

print("\nGoodbye.")
