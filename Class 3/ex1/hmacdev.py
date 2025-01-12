import hashlib
import hmac
import random

# Function to generate HMAC-SHA256
def hmac_sha256(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).digest()

# Function to truncate HMAC to 16 bits
def hmac_16bit(key, message):
    full_hmac = hmac_sha256(key, message)
    return full_hmac[:2]

def main():
    key = "clédefou"
    message = "Alice,Bob,£10"
    original_hmac = hmac_16bit(key, message)

    print(f"Original HMAC (16-bit): {original_hmac.hex()}")

    forged_message = "Alice,Eve,£1000"
    forged_hmac = original_hmac
    bank_computed_hmac = hmac_16bit(key, forged_message)

    if forged_hmac == bank_computed_hmac:
        print("Message accepted!")
    else:
        print("Message rejected! The HMAC does not match the message.")

    print("\nEve's Brute-Force Attack Simulation:")
    attempts = 0
    while True:
        attempts += 1
        fake_hmac = random.randbytes(2)
        if fake_hmac == bank_computed_hmac:
            break
    print(f"Eve succeeded after {attempts} attempts.")
if __name__ == "__main__":
    main()
