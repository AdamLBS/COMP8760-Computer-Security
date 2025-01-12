from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import random

# Encrypt function
def encrypt_aes(message: str, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 256 bits (32 bytes) long.")

    iv = os.urandom(16)

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return iv + ciphertext

# Decrypt function
def decrypt_aes(ciphertext: bytes, key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("Key must be 256 bits (32 bytes) long.")

    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(actual_ciphertext) + decryptor.finalize()

    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()

    return message.decode()

def generate_nonce() -> bytes:
    """
    Generates a random nonce as decimal.
    """
    return random.randint(0, 2**64)

def generate_key() -> bytes:
    """
    Generates a random 32-byte key.
    :return: The generated key.
    """
    return os.urandom(32).hex()

def send_first_step(sender, receiver, nonce):
    """
    Sends the first step of the Needham-Schroeder protocol.
    :param sender: The sender's name.
    :param receiver: The receiver's name.
    :param key: The shared key.
    :param nonce: The nonce.
    :return: The first message.
    """
    # Send the message
    return sender, receiver, nonce


# Example Usage
if __name__ == "__main__":
    # Generate a 256-bit (32-byte) key (should be securely generated in a real system)
    key = bytes.fromhex(generate_key())
    alice_server_key = bytes.fromhex(generate_key())
    bob_server_key = bytes.fromhex(generate_key())
    alice_bob_key = bytes.fromhex(generate_key())
    alice_nonce  = generate_nonce()
    print("Pre-shared keys between Alice and Server: ", alice_server_key.hex())
    print("Pre-shared keys between Bob and Server: ", bob_server_key.hex())
    print("")
    print("1 (Alice) : N_A = ", alice_nonce)
    print("1 (Alice => Server) : (A, B, N_A) = (Alice, Bob,", alice_nonce, ")")
    print("")
    print("2 (Server) : K_AB = ", alice_bob_key.hex())
    encrypt_aes("Alice", alice_bob_key)
    step1msg = alice_bob_key.hex() + ", " + "Alice"
    print(step1msg)
    encrypted_message = encrypt_aes(step1msg, bob_server_key)
    print(encrypted_message.hex())
    print("2 (Server) : E{K_BS} (K_AB, A) = E_{", bob_server_key.hex(), "} (", alice_bob_key.hex(), ", Alice) = " , encrypted_message.hex())
    step2msg1 = str(alice_nonce) + ", Bob, " + alice_bob_key.hex() + ", " + encrypted_message.hex()
    encrypted_message1 = encrypt_aes(step2msg1, alice_server_key)
    print("2 (Server => Alice) : E{K_AS} (N_A, B, K_AB, E_{K_BS} (K_AB, A)) = E_{"
          , alice_server_key.hex(), "} (", alice_nonce, ", Bob, ", alice_bob_key.hex(), ", ", encrypted_message.hex(), ") = ", encrypted_message1.hex())
    print("2 (Alice): (N_A, B, K_AB, E_{K_BS} (K_AB, A) = ", decrypt_aes(encrypted_message1, alice_server_key))
    if decrypt_aes(encrypted_message1, alice_server_key) == str(alice_nonce) + ", Bob, " + alice_bob_key.hex() + ", " + encrypted_message.hex():
        print("=> Message 2 authentication is successful")
    else:
        print("=> Message 2 authentication is failed")
        exit(1)
    print("")

    step3msg = alice_bob_key.hex() + ", " + "Alice"
    encrypted_message = encrypt_aes(step3msg, bob_server_key)
    print("3 (Alice => Bob ) : E_{K_BS} (K_AB, A) = E_{", bob_server_key.hex(), "} (", alice_bob_key.hex(), ", Alice) = ", encrypted_message.hex())
    print("3 (Bob): (K_AB, A) = ", decrypt_aes(encrypted_message, bob_server_key))
    if decrypt_aes(encrypted_message, bob_server_key) == step3msg:
        print("=> Message 3 authentication is successful")
    else:
        print("=> Message 3 authentication is failed")
        exit(1)
    print("")
    bob_nonce = generate_nonce()
    print("4 (Bob) : N_B = ", bob_nonce)
    print("4 (Bob => Alice) : E_{K_AB} (N_B) = E_{", alice_bob_key.hex(), "} (", bob_nonce, ") = ", encrypt_aes(str(bob_nonce), alice_bob_key).hex())
    print("4 (Alice): N_B = ", decrypt_aes(encrypt_aes(str(bob_nonce), alice_bob_key), alice_bob_key))
    if decrypt_aes(encrypt_aes(str(bob_nonce), alice_bob_key), alice_bob_key) == str(bob_nonce):
        print("=> Message 4 authentication is successful")
    else:
        print("=> Message 4 authentication is failed")
        exit(1)
    print("5 (Alice => Bob): E_{K_AB} (N_B - 1) = E_{", alice_bob_key.hex(), "} (", bob_nonce - 1, ") = ", encrypt_aes(str(bob_nonce - 1), alice_bob_key).hex())
    print("5 (Bob): N_B - 1 = ", decrypt_aes(encrypt_aes(str(bob_nonce - 1), alice_bob_key), alice_bob_key))
    if decrypt_aes(encrypt_aes(str(bob_nonce - 1), alice_bob_key), alice_bob_key) == str(bob_nonce - 1):
        print("=> Message 5 authentication is successful")
    else:
        print("=> Message 5 authentication is failed")
        exit(1)
    print("")
    print("The key agreed between Alice and Bob is ", alice_bob_key.hex())
