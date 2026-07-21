import os
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

# Loads the variables from the .env file into the environment
load_dotenv()

# Retrieves the keys (with a default value)
AES_GCM_KEY = os.getenv("AES_GCM_KEY", "32CharacterSecretKeyByDefault!!!").encode('utf-8')

# ==========================================
# Steganography
# ==========================================
def to_8bit(c):
    binary_string = bin(ord(c))[2:]
    return "0"*(8-len(binary_string))+binary_string

def modify_pixel(pixel, bit):
    r_val = pixel[0]
    binary_rep = bin(r_val)[2:]
    mod_bin_rep = binary_rep[:-1] + bit
    r_val = int(mod_bin_rep, 2)
    return tuple([r_val] + list(pixel[1:]))

def hide_data(input_image_path, jwt_token, binary_timestamp, output_path):
    print("-> AEAD Encryption and Steganographic Injection...")
    
    # Prepare data with a clear separator (|||)
    raw_data = jwt_token.encode('utf-8') + b'|||' + binary_timestamp
    
    # AEAD Encryption (AES-GCM)
    aesgcm = AESGCM(AES_GCM_KEY)
    nonce = os.urandom(12) # The nonce must be unique (12 standard bytes)
    encrypted_data = aesgcm.encrypt(nonce, raw_data, None)
    
    # Final payload = Nonce + Ciphertext + End marker
    payload_bytes = nonce + encrypted_data + b'===END==='
    
    # Bit conversion and injection 
    bits_to_hide = ''.join([format(b, '08b') for b in payload_bytes])
    bit_length = len(bits_to_hide)
    
    img = Image.open(input_image_path)
    pixels = img.load()
    width, height = img.size
    
    bit_idx = 0
    for y in range(height):
        for x in range(width):
            if bit_idx < bit_length:
                pixels[x, y] = modify_pixel(pixels[x, y], bits_to_hide[bit_idx])
                bit_idx += 1
            else:
                break
        if bit_idx >= bit_length:
            break
            
    img.save(output_path)
    print(f"-> Steganographic and encrypted image saved!")

def extract_data(image_path):
    print("-> Extraction and AEAD Decryption in progress...")
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size
    
    extracted_bits = ""
    for y in range(height):
        for x in range(width):
            r_val = pixels[x, y][0]
            binary_rep = bin(r_val)[2:]
            extracted_bits += binary_rep[-1]
            
    extracted_bytes = bytearray()
    for i in range(0, len(extracted_bits), 8):
        byte = extracted_bits[i:i+8]
        if len(byte) == 8:
            extracted_bytes.append(int(byte, 2))
            
    marker = b"===END==="
    end_index = extracted_bytes.find(marker)
    
    if end_index != -1:
        useful_data = extracted_bytes[:end_index]
        
        # Separation Nonce (first 12 bytes) / Ciphertext (The rest)
        nonce = useful_data[:12]
        encrypted_data = useful_data[12:]
        
        # AEAD Decryption (Guarantees confidentiality AND integrity)
        try:
            aesgcm = AESGCM(AES_GCM_KEY)
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        except Exception as e:
            print("AEAD decryption failed (Invalid password or alteration!)")
            return None, None

        # Separation JWT / Timestamp via our separator
        parts = decrypted_data.split(b'|||', 1)
        if len(parts) == 2:
            jwt_token = parts[0].decode('utf-8')
            binary_timestamp = parts[1]
            return jwt_token, binary_timestamp
            
    return None, None