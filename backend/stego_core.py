# stego_core.py
# Optimized core logic library for steganography operations.

import os
import io
import numpy as np
from PIL import Image
import wave
from abc import ABC, abstractmethod
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- Constants ---
SALT_SIZE = 16
KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 16
AES_GCM_TAG_SIZE = 16
PBKDF2_ITERATIONS = 1_000_000 # Using underscore for readability
APPEND_MAGIC_MARKER = b"!!STEGO_SECRET_SAUCE!!"
PAYLOAD_LEN_BYTES = 4
FILENAME_LEN_BYTES = 1

# --- Core Classes ---

class CryptoEngine:
    """Handles encryption and decryption using AES-GCM with a key derived from a password."""
    def __init__(self, password: str):
        self.password = password.encode('utf-8')

    def _derive_key(self, salt: bytes) -> bytes:
        """Derives a cryptographic key from the password and salt using PBKDF2."""
        return PBKDF2(self.password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypts plaintext and returns a payload: salt + nonce + tag + ciphertext."""
        salt = get_random_bytes(SALT_SIZE)
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        # The nonce is generated automatically and stored in cipher.nonce
        return salt + cipher.nonce + tag + ciphertext

    def decrypt(self, payload: bytes) -> bytes | None:
        """Decrypts a payload, verifies its integrity, and returns the original plaintext."""
        try:
            salt = payload[:SALT_SIZE]
            nonce = payload[SALT_SIZE : SALT_SIZE + AES_GCM_NONCE_SIZE]
            tag = payload[SALT_SIZE + AES_GCM_NONCE_SIZE : SALT_SIZE + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE]
            ciphertext = payload[SALT_SIZE + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:]

            key = self._derive_key(salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            # Error during decryption, likely wrong password or corrupt data
            return None

class MediaHandler(ABC):
    """Abstract base class for handling media files."""
    @abstractmethod
    def read(self, file_path: str) -> tuple[np.ndarray, dict | None]:
        """Reads media file into a numpy array and returns metadata."""
        pass

    @abstractmethod
    def write(self, file_path: str, data_array: np.ndarray, params: dict | None) -> None:
        """Writes a numpy array to a media file using provided metadata."""
        pass

class PngHandler(MediaHandler):
    """Handles reading and writing PNG image files."""
    def read(self, file_path: str) -> tuple[np.ndarray, None]:
        img = Image.open(file_path).convert('RGB')
        return np.array(img, dtype=np.uint8), None

    def write(self, file_path: str, data_array: np.ndarray, params: None = None) -> None:
        Image.fromarray(data_array).save(file_path, 'PNG')

class WavHandler(MediaHandler):
    """Handles reading and writing WAV audio files."""
    def read(self, file_path: str) -> tuple[np.ndarray, dict]:
        with wave.open(file_path, 'rb') as wf:
            params = wf.getparams()
            frames = wf.readframes(wf.getnframes())
            return np.frombuffer(frames, dtype=np.uint8), params

    def write(self, file_path: str, data_array: np.ndarray, params: dict) -> None:
        with wave.open(file_path, 'wb') as wf:
            wf.setparams(params)
            wf.writeframes(data_array.tobytes())

class LsbEngine:
    """Performs LSB steganography using efficient NumPy operations."""
    def hide(self, cover_data: np.ndarray, payload: bytes) -> np.ndarray:
        """Hides payload into the LSBs of the cover data."""
        data_to_hide = len(payload).to_bytes(PAYLOAD_LEN_BYTES, 'big') + payload
        num_bits_to_hide = len(data_to_hide) * 8

        if num_bits_to_hide > cover_data.size:
            raise ValueError("Payload is too large for the cover media.")

        # Unpack payload bytes into a bit array (e.g., b'\x05' -> [0,0,0,0,0,1,0,1])
        bits_to_hide = np.unpackbits(np.frombuffer(data_to_hide, dtype=np.uint8))
        
        stego_data = cover_data.flatten()
        # Clear the LSB of the required portion of the cover data
        stego_data[:num_bits_to_hide] &= 0b11111110
        # Embed the payload bits using OR
        stego_data[:num_bits_to_hide] |= bits_to_hide
        
        return stego_data.reshape(cover_data.shape)

    def extract(self, stego_data: np.ndarray) -> bytes:
        """Extracts a payload from the LSBs of the stego data."""
        flat_stego = stego_data.flatten()
        
        # Extract LSBs for the header to determine payload length
        header_bits = flat_stego[:PAYLOAD_LEN_BYTES * 8] & 1
        header_bytes = np.packbits(header_bits)
        payload_len = int.from_bytes(header_bytes.tobytes(), 'big')
        
        total_bits_to_extract = (PAYLOAD_LEN_BYTES + payload_len) * 8
        if total_bits_to_extract > flat_stego.size:
            raise ValueError("Data size mismatch or corruption detected.")
            
        # Extract all relevant LSBs (header + payload)
        data_bits = flat_stego[:total_bits_to_extract] & 1
        # Convert bit array back to bytes and slice off the header to get the payload
        extracted_bytes = np.packbits(data_bits).tobytes()
        
        return extracted_bytes[PAYLOAD_LEN_BYTES:]

class AppendEngine:
    """Hides data by appending it to the end of a file, marked with a magic number."""
    def hide(self, cover_path: str, output_path: str, payload: bytes) -> None:
        with open(cover_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(f_in.read())
            f_out.write(APPEND_MAGIC_MARKER)
            f_out.write(payload)

    def extract(self, stego_path: str) -> bytes:
        with open(stego_path, 'rb') as f:
            data = f.read()
        marker_pos = data.rfind(APPEND_MAGIC_MARKER)
        if marker_pos == -1:
            raise ValueError("Steganography marker not found.")
        return data[marker_pos + len(APPEND_MAGIC_MARKER):]

# --- Main Functions ---

CONFIG = {
    ".png": {"strategy": "lsb", "handler": PngHandler()},
    ".wav": {"strategy": "lsb", "handler": WavHandler()}
}
DEFAULT_STRATEGY = {"strategy": "append", "handler": None}

def hide_data(cover_path: str, secret_path: str, password: str, output_path: str, message: str | None = None) -> None:
    """Main function to hide a secret file and an optional message within a cover file."""
    ext = os.path.splitext(cover_path)[1].lower()
    tech = CONFIG.get(ext, DEFAULT_STRATEGY)
    strategy = tech["strategy"]

    # 1. Prepare Payload
    original_filename = os.path.basename(secret_path).encode('utf-8')
    if len(original_filename) > 255:
        raise ValueError("Filename is too long (max 255 bytes).")
    
    with open(secret_path, 'rb') as f:
        filedata = f.read()

    message_bytes = message.encode('utf-8') if message else b''

    # Use a stream for cleaner payload construction
    payload_stream = io.BytesIO()
    payload_stream.write(len(message_bytes).to_bytes(PAYLOAD_LEN_BYTES, 'big'))
    payload_stream.write(message_bytes)
    payload_stream.write(len(original_filename).to_bytes(FILENAME_LEN_BYTES, 'big'))
    payload_stream.write(original_filename)
    payload_stream.write(filedata)
    plaintext_payload = payload_stream.getvalue()
    
    # 2. Encrypt Payload
    encrypted_payload = CryptoEngine(password).encrypt(plaintext_payload)

    # 3. Hide Payload
    if strategy == "lsb":
        handler = tech["handler"]
        cover_data, params = handler.read(cover_path)
        stego_data = LsbEngine().hide(cover_data, encrypted_payload)
        handler.write(output_path, stego_data, params)
    else: # Append strategy
        AppendEngine().hide(cover_path, output_path, encrypted_payload)

def extract_data(stego_path: str, password: str) -> tuple[bytes, str, str] | tuple[None, None, None]:
    """Main function to extract a secret file and message from a stego file."""
    ext = os.path.splitext(stego_path)[1].lower()
    tech = CONFIG.get(ext, DEFAULT_STRATEGY)
    strategy = tech["strategy"]

    # 1. Extract Encrypted Payload
    try:
        if strategy == "lsb":
            handler = tech["handler"]
            stego_data, _ = handler.read(stego_path)
            encrypted_payload = LsbEngine().extract(stego_data)
        else: # Append strategy
            encrypted_payload = AppendEngine().extract(stego_path)
    except (ValueError, FileNotFoundError):
        return None, None, None

    # 2. Decrypt Payload
    decrypted_payload = CryptoEngine(password).decrypt(encrypted_payload)
    if not decrypted_payload:
        return None, None, None

    # 3. Parse Payload
    try:
        payload_stream = io.BytesIO(decrypted_payload)
        
        message_len = int.from_bytes(payload_stream.read(PAYLOAD_LEN_BYTES), 'big')
        message = payload_stream.read(message_len).decode('utf-8', errors='replace')
        
        filename_len = int.from_bytes(payload_stream.read(FILENAME_LEN_BYTES), 'big')
        filename = payload_stream.read(filename_len).decode('utf-8', errors='replace')
        
        filedata = payload_stream.read() # Read the rest of the stream
        
        return filedata, filename, message
    except (IndexError, ValueError):
        # Error parsing payload, indicates corruption or wrong format
        return None, None, None
# --- End of stego_core.py ---