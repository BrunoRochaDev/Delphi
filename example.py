# This file is not part of the framework itself!
# It is simply an example demonstrating how to integrate and use the framework in your own Python project.
# As you'll see, the process involves importing the `decrypt_ciphertext` and `forge_ciphertext` functions,
# implementing your own oracle function, and utilizing these components together.
# Please note that this tool is intended for educational purposes only and should not be used for malicious activities.
# - BRM

from delphi import decrypt, encrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# This is the encryption key that was used to encrypt the sample data in this demonstration.
# In a real-world scenario, an attacker would not have access to this key.
# However, the purpose of this attack is to perform encryption and decryption operations without directly knowing the key.
ENCRYPTION_KEY = b'AnEncryptionKeyThatIs32BytesLong'

# This is a ciphertext that was previously encrypted using the above encryption key.
SECRET_TO_DECRYPT = bytearray([0xe3, 0xcf, 0x3d, 0x13, 0xc9, 0xfc, 0x5d, 0xcf,
                               0x30, 0x0f, 0xcf, 0x9a, 0xbd, 0xd8, 0x6b, 0xaf,
                               0x6a, 0x7e, 0x56, 0x2c, 0xa9, 0xb1, 0xe7, 0x70,
                               0x81, 0x1e, 0x04, 0xdd, 0x09, 0xe4, 0xae, 0xae])

# This is a piece of plaintext that we intend to encrypt using the encryption key.
STRING_TO_ENCRYPT = b'EncryptMe!'


# This is an example of an Oracle function that will be used by the cryptographic framework.
# When adapting this framework for your own purposes, you should create a similar function that interacts with **your chosen source** (e.g., a server, service, or other component).
# Based on this interaction, you should infer whether the padding of the ciphertext is valid and return either True or False.
# For instance, you might make an HTTP request to an endpoint and determine padding validity based on the status code or other aspects of the response.
def consult_oracle(iv : bytes, ciphertext : bytes) -> bool:
    # Creates an AES cipher object using the predefined encryption key and the provided IV.
    # The cipher mode used is CBC, as required for the attack.
    aes = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)

    # Decrypts the provided ciphertext using the AES cipher, producing the raw decrypted plaintext (including padding).
    plaintext = aes.decrypt(ciphertext)
    try:
        # Attempts to remove the padding from the decrypted plaintext.
        # Note: the unpad function uses PKCS#7 as the default padding scheme.
        unpad(plaintext, AES.block_size)
    # If the ciphertext has invalid padding (i.e., the padding cannot be removed properly), the unpad function will raise a ValueError exception.
    except ValueError:
        # If a ValueError is raised, the padding is invalid, and the function returns False.
        return False

    # If no exception is raised, the padding is valid, and the function returns True.
    return True

# Demonstrating the framework.
if __name__ == "__main__":
    # DECRYPTION ATTACK DEMONSTRATION
    print("Decrypting secret...")

    # Separate the IV from the rest of the ciphertext.
    # The IV is the first block of the ciphertext, while the remaining data is the actual ciphertext.
    iv = SECRET_TO_DECRYPT[:AES.block_size]
    ciphertext = SECRET_TO_DECRYPT[AES.block_size:]

    # Call the framework's decryption function to decrypt the ciphertext.
    # We provide the IV, the ciphertext, and the oracle function (consult_oracle) as arguments.
    plaintext = decrypt(iv, ciphertext, consult_oracle)

    # The decrypted plaintext will still contain padding. We remove the padding using the unpad function.
    plaintext = unpad(plaintext, AES.block_size)
    print(f"Recovered secret: {plaintext.decode('utf-8')}")
    
    # ENCRYPTION ATTACK DEMONSTRATION
    print("Encrypting string...")
    
    # To encrypt an arbitrary string, we use the framework's forging function.
    # We provide the string to be encrypted and the oracle function as arguments.
    iv, ciphertext = encrypt(STRING_TO_ENCRYPT, consult_oracle)
    print(f"Encrypted string: {STRING_TO_ENCRYPT.decode('utf-8')} -> {iv.hex()} (IV) + {ciphertext.hex()} (Ciphertext)")