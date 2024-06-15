import struct

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def left_rotate(value, shift, width=32):
    return ((value << shift) & (2**width - 1)) | (value >> (width - shift))

def f_function(right, key):
    # Convert bytes to integer
    right_int = int.from_bytes(right, 'big')
    key_int = int.from_bytes(key, 'big')
    
    # Combine operations: XOR, left rotation, and addition
    result = right_int ^ key_int
    result = left_rotate(result, 5)
    result = (result + key_int) % (2**32)
    
    # Convert integer back to bytes
    result_bytes = result.to_bytes((result.bit_length() + 7) // 8, 'big')
    return result_bytes

def generate_subkeys(key, num_rounds):
    # Convert key to bytes
    key_bytes = key.encode()
    subkeys = []
    for i in range(num_rounds):
        subkey = xor_bytes(key_bytes, struct.pack(">I", i))
        subkeys.append(subkey)
    return subkeys

def feistel_round(left, right, key):
    new_left = right
    f_output = f_function(right, key)
    new_right = xor_bytes(left, f_output)
    return new_left, new_right

def feistel_encrypt(plaintext, keys):
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode()
    left = plaintext_bytes[:len(plaintext_bytes)//2]
    right = plaintext_bytes[len(plaintext_bytes)//2:]

    for key in keys:
        left, right = feistel_round(left, right, key)

    return left + right

def feistel_decrypt(ciphertext, keys):
    left = ciphertext[:len(ciphertext)//2]
    right = ciphertext[len(ciphertext)//2:]

    for key in reversed(keys):
        right, left = feistel_round(right, left, key)

    return left + right

# Take input from the user
master_key = input("Enter your secret key: ")
plaintext = input("Enter plaintext input: ")
num_rounds = 4  # You can adjust the number of rounds as needed

# Generate subkeys
keys = generate_subkeys(master_key, num_rounds)

# Encryption
ciphertext_bytes = feistel_encrypt(plaintext, keys)
print("Ciphertext (hex):", ciphertext_bytes.hex())

# Decryption
decrypted_text_bytes = feistel_decrypt(ciphertext_bytes, keys)
print("Decrypted text (bytes):", decrypted_text_bytes)

# Convert decrypted bytes to string (assuming it's plaintext)
try:
    decrypted_text = decrypted_text_bytes.decode('utf-8')
    print("Decrypted text (utf-8):", decrypted_text)
except UnicodeDecodeError:
    print("Decoding error: Cannot decode decrypted bytes to utf-8.")
