from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import random

def encrypt_aes(message: str, key: bytes) -> bytes:
    """
    Encrypts a message using AES-256-CBC with PKCS7 padding.
    :param message: The plaintext message to encrypt.
    :param key: The encryption key (32 bytes).
    :return: The ciphertext with the IV prepended.
    """
    if len(key) != 32:
        raise ValueError("Key must be 256 bits (32 bytes) long.")

    # Generate a random IV
    iv = os.urandom(16)

    # Add PKCS7 padding to the plaintext
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Return IV + ciphertext
    return iv + ciphertext

def decrypt_aes(ciphertext: bytes, key: bytes) -> str:
    """
    Decrypts a ciphertext using AES-256-CBC with PKCS7 padding.
    :param ciphertext: The ciphertext with the IV prepended.
    :param key: The decryption key (32 bytes).
    :return: The decrypted plaintext.
    """
    if len(key) != 32:
        raise ValueError("Key must be 256 bits (32 bytes) long.")

    # Extract the IV and actual ciphertext
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # Decrypt the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
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
    bob_server_key = bytes.fromhex('cea37bddf68b837300aceb7ef44b3cb44ec21102b5d3acf25598b6e7987a913f')
    alice_bob_key = bytes.fromhex('848f340909b78b519309ab9204cdde5cfaa2de75be39e7f8200b771a0940e7f1')
    alice_nonce  = generate_nonce()
    utt = bytes.fromhex('4403c123b7fbdd037a2bf4c8380cc98149c8a8e605654c0ed8e4fdc26739b9ad08a407056260bdccd3ae5b78d926a5e50fb64ace8bba43bd147bc04ecafd2e810eeac29e67c4cdfc19b219017a2454a298dfed1504c8cdf7072fe956dc56a96b')
    print("Unknown to Eve:")
    print("Pre-shared keys between Alice and Server: [does not matter / unused in the attack]")
    print("Pre-shared keys between Bob and Server: ", bob_server_key.hex())
    print("")
    print("Known to Eve (collected from a previous session between Alice and Bob):")
    print("Pre-recorded K_AB: ", alice_bob_key.hex())
    print("Pre-recorded Message 3 (Alice => Bob): ", mes.hex())
    print("")
    step3msg = str(alice_bob_key.hex()) + ", " + "Alice"
    encrypted_message = encrypt_aes(step3msg, bob_server_key)
    print("3 (Eve => Bob ) : E_{K_BS} (K_AB, A) = E_{", bob_server_key.hex(), "} (", alice_bob_key.hex(), ", Alice) = ", encrypted_message.hex())
    print("3 (Bob): (K_AB, A) = ", decrypt_aes(encrypted_message, bob_server_key))
    if decrypt_aes(encrypted_message, bob_server_key) == step3msg:
        print("=> Eve successfully passed Message 3 authentication")
    else:
        print("=> Message 3 authentication is failed")
        exit(1)
    print("")
    bob_nonce = generate_nonce()
    print("4 (Bob) : N_B = ", bob_nonce)
    print("4 (Bob => Eve) : E_{K_AB} (N_B) = E_{", alice_bob_key.hex(), "} (", bob_nonce, ") = ", encrypt_aes(str(bob_nonce), alice_bob_key).hex())
    print("4 (Eve): N_B = ", decrypt_aes(encrypt_aes(str(bob_nonce), alice_bob_key), alice_bob_key))
    if decrypt_aes(encrypt_aes(str(bob_nonce), alice_bob_key), alice_bob_key) == str(bob_nonce):
        print("=> Eve successfully decrypted Message 4 to get N_B")
    else:
        print("=> Message 4 authentication is failed")
        exit(1)
    print("5 (Eve => Bob): E_{K_AB} (N_B - 1) = E_{", alice_bob_key.hex(), "} (", bob_nonce - 1, ") = ", encrypt_aes(str(bob_nonce - 1), alice_bob_key).hex())
    print("5 (Bob): N_B - 1 = ", decrypt_aes(encrypt_aes(str(bob_nonce - 1), alice_bob_key), alice_bob_key))
    if decrypt_aes(encrypt_aes(str(bob_nonce - 1), alice_bob_key), alice_bob_key) == str(bob_nonce - 1):
        print("=> Message 5 authentication is successful")
    else:
        print("=> Message 5 authentication is failed")
        exit(1)
    print("")
    print("Eve successfully launched a replay attack to reus a previouslly recorded session key agreed between Eve and Bob ", alice_bob_key.hex())