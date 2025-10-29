from Crypto.Util.Padding import pad

BLOCK_SIZE = 16
DEBUG = True

def decrypt(iv : bytes, ciphertext : bytes, oracle : callable) -> bytes:
    """
    Decrypts a valid ciphertext using a CBC Padding Oracle attack.

    Args:
    iv (bytes): The initialization vector for the ciphertext. If the IV is None, it will be assumed that the attacker doesn't control the IV, which will mean the first block of ciphertext cannot be decrypted.
    ct (bytes): The ciphertext to decrypt.
    oracle (callable): A function that checks if a ciphertext has valid padding. Must return true or false.

    Returns:
    bytes: The decrypted plaintext corresponding to the given ciphertext.
    """

    # Ensure correct sizes the ciphertext.
    assert len(ciphertext) % BLOCK_SIZE == 0
    
    # If an IV was provided...
    if iv:
        # Ensure correct sizes for the IV, if provided.
        assert len(iv) == BLOCK_SIZE
    # If an IV was not provided...
    else:
        print("WARNING: The IV was not provided. The attack will proceed, however, without control over the IV, decryption of the first block of ciphertext will not be possible.")

    # Split ciphertext into blocks for decryption.
    blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

    # Prepare to accumulate decrypted plaintext across blocks.
    result = b''
    
    # The XOR value for the first block is the IV. This will change for other blocks.
    xor_value = iv

    # Decrypt each block in the ciphertext sequentially.
    for idx, ciphertext in enumerate(blocks):
        # If an IV was not provided, we cannot decrypt the first block.
        if xor_value:
            # Perform a brute force attack to find the intermediary value for the ciphertext.
            intermediary_value = _get_intermediary_value(ciphertext, oracle)

            # Recover the plaintext by XORing the XOR value with the intermadiary value.
            plaintext = bytes(a ^ b for a, b in zip(xor_value, intermediary_value))

            # Append the discovered plaintext to the overall result.
            result += plaintext

        # Set the IV for the next block the current ciphertext block.
        xor_value = ciphertext

        # Print progress if debug is enabled.
        if DEBUG:
            print(f'Block completed [{idx+1}/{len(blocks)}]')

    # In case IV was not provided, warn that the result does not include the first block.
    if not iv:
        print("WARNING: Attack was successful, but the first block of plaintext was not recovered. Returning the plaintext for the remaining blocks.")

    # Return the fully decrypted plaintext.
    return result

def encrypt(plaintext : bytes, oracle : callable, controls_iv : bool = True) -> tuple[bytes, bytes]:
    """
    Exploits a CBC Padding Oracle attack to forge a valid ciphertext from a provided plaintext.

    Args:
    plaintext (bytes): The plaintext to encrypt.
    oracle (callable): A function that checks if a ciphertext has valid padding. Must return true or false.
    controls_iv (bool, optional): Indicates whether the attacker controls the IV. Defaults to True. If set to False, the forged ciphertext will decrypt to a plaintext with an additional block of junk data before the intended plaintext.

    Returns:
    tuple[bytes, bytes]: The IV (or None if controls_iv is False) and the forged ciphertext bytes.
    """
    
    # In case the IV cannot be controlled by the attacker.
    if not controls_iv:
        print("WARNING: Without control of the IV, the forged ciphertext will decrypt to a plaintext with a block of junk before the intended plaintext.")

    # Pad the plaintext to ensure it matches the required block size.
    plaintext = pad(plaintext, BLOCK_SIZE)

    # Split plaintext into blocks.
    plaintext_blocks = [plaintext[i:i+BLOCK_SIZE] for i in range(0, len(plaintext), BLOCK_SIZE)]

    # Initialize the process by creating a block filled with junk data (zeros in this case).
    # This block serves as the final block of the ciphertext, to which additional blocks will be prepended in the loop.
    # For the first iteration, this junk block will act as the "previous block".
    prev_block = bytearray(BLOCK_SIZE)
    result = prev_block
    
    # Encrypt plaintext blocks in reverse order.
    for idx, block in enumerate(reversed(plaintext_blocks)):
        # Discover the intermadiary value for the previous ciphertext block.
        intermediary_value = _get_intermediary_value(prev_block, oracle)

        # Discover the XOR value by XORing the intermediary value with the plaintext block.
        new_block = bytes(a ^ b for a, b in zip(intermediary_value, block))

        # Prepend the new block to the result being assembled.
        result = new_block + result

        # Update the previous block to the newly created block for the next iteration.
        prev_block = new_block

        # Print progress if debug is enabled.
        if DEBUG:
            print(f'Block completed [{idx+1}/{len(plaintext_blocks)}]')

    # If the IV is controllable, the first block of the result will be the IV.
    if controls_iv:
        # The IV is be the first block of the forged ciphertext.
        iv = result[:BLOCK_SIZE]
        # The remaining blocks are the ciphertext properly.
        ciphertext = result[BLOCK_SIZE:]
    # If the IV cannot be controlled, then we whole result is the ciphertext.
    else:
        iv = None
        ciphertext = result

    return iv, ciphertext

def _get_intermediary_value(block : bytes, oracle : callable) -> bytes:
    # The zeroing IV will start with just zeros.
    # The zeroing IV is the same thing as the the intermediate value of the ciphertext, because if `intermediate_value XOR zeroing_iv = zeros`, then `intermediate_value = zeroing_iv`.
    zeroing_iv = [0] * BLOCK_SIZE

    # Iterate over each possible padding length from 1 onward up to the block size.
    for pad_val in range(1, BLOCK_SIZE+1):
        # Create a padding IV by XORing the zeroing IV with the padding length.
        padding_iv = [0] * (BLOCK_SIZE - pad_val)                   # For this attack, the values of these bytes are not relevant.
        padding_iv += [pad_val ^ b for b in zeroing_iv[-pad_val:]]  # XORing the zeroing IV with the padding length.

        # Test all possible byte values from 0 to 255 for the current padding position.
        for candidate in range(256):
            # Set the current padding position to the candidate byte value.
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)

            # Check if the oracle validates the padding for the current IV and block.
            if oracle(iv, block):
                # While trying to find the value for the last byte, there's an edge case we need to test. 
                if pad_val == 1:
                    # It is possible that this block has a valid padding of [..., 0x02, 0x02] instead of [..., 0x01].
                    # In that case, we modify the penultimate block and query the oracle again.
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)

                    # If the oracle no longer validates, then it's a false positive and the padding was [..., 0x02, 0x02].
                    # Retry other candidates.
                    if not oracle(iv, block):
                        continue

                # Correct candidate found, exit loop.
                break
        else:
            # If no valid byte is found, then there must be something wrong with the oracle.
            raise Exception("No valid padding byte found. Is the oracle working correctly?")

        # Calculate the correct byte for the zeroing IV by XOR'ing the candidate with the current padding value and update the zeroing IV's corresponding position.
        zeroing_iv[-pad_val] = candidate ^ pad_val

        # Print progress if debug is enabled.
        if DEBUG:
            print(f'Byte completed [{pad_val}/{BLOCK_SIZE}]')

    return zeroing_iv

