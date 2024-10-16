import os

# S-box used for SubBytes
S_BOX = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

# Rcon used for KeyExpansion
RCON = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

def gmul(a, b):
    """Galois Field (256) Multiplication of two Bytes."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1b  # AES irreducible polynomial
        b >>= 1
    return p

def sub_bytes(state):
    """Apply the S-box substitution to the state."""
    for i in range(4):
        for j in range(4):
            byte = state[i][j]
            state[i][j] = S_BOX[byte >> 4][byte & 0x0F]
    return state

def shift_rows(state):
    """Perform the ShiftRows transformation."""
    state[1] = state[1][1:] + state[1][:1]  # Left rotate by 1
    state[2] = state[2][2:] + state[2][:2]  # Left rotate by 2
    state[3] = state[3][3:] + state[3][:3]  # Left rotate by 3
    return state

def mix_single_column(column):
    """Mix one column for the MixColumns transformation."""
    temp = column.copy()
    column[0] = gmul(temp[0], 2) ^ gmul(temp[1], 3) ^ temp[2] ^ temp[3]
    column[1] = temp[0] ^ gmul(temp[1], 2) ^ gmul(temp[2], 3) ^ temp[3]
    column[2] = temp[0] ^ temp[1] ^ gmul(temp[2], 2) ^ gmul(temp[3], 3)
    column[3] = gmul(temp[0], 3) ^ temp[1] ^ temp[2] ^ gmul(temp[3], 2)
    return column

def mix_columns(state):
    """Perform the MixColumns transformation."""
    for i in range(4):
        column = [state[0][i], state[1][i], state[2][i], state[3][i]]
        mixed_column = mix_single_column(column)
        for j in range(4):
            state[j][i] = mixed_column[j]
    return state

def add_round_key(state, key_schedule, round_key_index):
    """Add the round key to the state."""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key_schedule[round_key_index + j][i]
    return state

def rot_word(word):
    """Rotate a word (4 bytes) left by one byte."""
    return word[1:] + word[:1]

def sub_word(word):
    """Apply the S-box substitution to a word (4 bytes)."""
    return [S_BOX[byte >> 4][byte & 0x0F] for byte in word]

def key_expansion(key):
    """Expand the cipher key into the key schedule."""
    key_symbols = [k for k in key]
    key_schedule = []
    for i in range(4):
        key_schedule.append(key_symbols[4*i:4*(i+1)])

    for i in range(4, 44):
        temp = key_schedule[i - 1][:]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4 - 1][0]
        word = [key_schedule[i - 4][j] ^ temp[j] for j in range(4)]
        key_schedule.append(word)
    return key_schedule

def aes_encrypt(plaintext, key):
    """Encrypt a single block of plaintext using AES."""
    state = [[plaintext[4 * i + j] for j in range(4)] for i in range(4)]
    key_schedule = key_expansion(key)

    state = add_round_key(state, key_schedule, 0)

    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key_schedule, round * 4)

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_schedule, 40)

    ciphertext = bytearray(16)
    for i in range(4):
        for j in range(4):
            ciphertext[4 * i + j] = state[i][j]
    return bytes(ciphertext)

def aes_encrypt_file(input_file, output_file, key):
    """Encrypt a file using AES encryption."""
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Padding (PKCS#7)
    padding_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_len] * padding_len)

    # Encryption
    ciphertext = b''
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        encrypted_block = aes_encrypt(block, key)
        ciphertext += encrypted_block

    # Determine if the file is a text file
    file_ext = os.path.splitext(input_file)[1].lower()
    if file_ext == '.txt':
        # Write ciphertext as hex string for text files
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(ciphertext.hex())  # Writing as hex string
    else:
        # Write ciphertext in binary mode for binary files
        with open(output_file, 'wb') as f:
            f.write(ciphertext)

def encrypt_files_in_directory(input_path, output_path, key):
    """Encrypt files with specified extensions in a directory."""
    # Create output directory if it doesn't exist
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    # Define the file extensions to encrypt
    file_extensions = ['.txt', '.jpg', '.jpeg', '.png', '.pdf']

    # List all files in the input directory
    for filename in os.listdir(input_path):
        # Get file extension
        file_ext = os.path.splitext(filename)[1].lower()
        # Check if the file has one of the specified extensions and is not already encrypted
        if file_ext in file_extensions and not filename.endswith('_E' + file_ext):
            input_file = os.path.join(input_path, filename)
            output_file = os.path.join(output_path, filename[:-len(file_ext)] + '_E' + file_ext)

            # Check if the encrypted file already exists to prevent overwriting
            if os.path.exists(output_file):
                print(f"Encrypted file already exists for {filename}, skipping encryption.")
                continue

            # Encrypt each file
            aes_encrypt_file(input_file, output_file, key)
            print(f'File {filename} encrypted and saved as {output_file}')

if __name__ == "__main__":
    # Define your input and output directories
    input_path = "C:\\Users\\xapa\\Documents\\test"
    output_path = "C:\\Users\\xapa\\Documents\\test\\enc"

    # Define your AES key (16 bytes for AES-128)
    key_input = "qwertyuiopqwerty"
    key = key_input.encode('utf-8')

    # Validate key length
    if len(key) != 16:
        print("The key must be exactly 16 bytes long.")
    else:
        encrypt_files_in_directory(input_path, output_path, key)