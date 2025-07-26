# stego_core.py
# This is the core logic library, refactored from the original scripts.
# It contains no command-line code and is designed to be imported.

import os
import numpy as np
from PIL import Image
import wave
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# --- All your classes remain the same ---

class CryptoEngine:
    def __init__(self, password: str):
        self.password = password.encode('utf-8')
        self.salt_size = 16
        self.key_size = 32
        self.iterations = 1000000
    def _derive_key(self, salt: bytes) -> bytes:
        return PBKDF2(self.password, salt, dkLen=self.key_size, count=self.iterations)
    def encrypt(self, plaintext: bytes) -> bytes:
        salt = get_random_bytes(self.salt_size)
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return salt + cipher.nonce + tag + ciphertext
    def decrypt(self, payload: bytes) -> bytes:
        try:
            # Corrected slicing for GCM payload
            salt = payload[:self.salt_size]
            nonce = payload[self.salt_size:self.salt_size + 16]
            tag = payload[self.salt_size + 16:self.salt_size + 32]
            ciphertext = payload[self.salt_size + 32:]
            key = self._derive_key(salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)
        except (ValueError, KeyError):
            return None

class PngHandler:
    def read(self, file_path):
        img = Image.open(file_path).convert('RGB'); return np.array(img, dtype=np.uint8)
    def write(self, file_path, data_array):
        Image.fromarray(data_array).save(file_path, 'PNG')

class WavHandler:
    def read(self, file_path):
        with wave.open(file_path, 'rb') as wf:
            self.params = wf.getparams(); return np.frombuffer(wf.readframes(wf.getnframes()), dtype=np.uint8)
    def write(self, file_path, data_array):
        with wave.open(file_path, 'wb') as wf:
            wf.setparams(self.params); wf.writeframes(data_array.tobytes())

class LsbEngine:
    def _data_to_bits(self, data): return "".join(f"{byte:08b}" for byte in data)
    def _bits_to_data(self, bits): return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    def hide(self, cover_data, payload):
        data_to_hide = len(payload).to_bytes(4, 'big') + payload
        if len(data_to_hide) * 8 > cover_data.size: raise ValueError("Payload too large.")
        bits = self._data_to_bits(data_to_hide)
        flat_cover = cover_data.flatten()
        for i in range(len(bits)): flat_cover[i] = (flat_cover[i] & 0b11111110) | int(bits[i])
        return flat_cover.reshape(cover_data.shape)
    def extract(self, stego_data):
        flat_stego = stego_data.flatten()
        header_bits = "".join(str(b & 1) for b in flat_stego[:32])
        payload_len = int(header_bits, 2)
        total_bits_to_extract = 32 + payload_len * 8
        if total_bits_to_extract > flat_stego.size: raise ValueError("Data size mismatch.")
        payload_bits = "".join(str(b & 1) for b in flat_stego[32 : total_bits_to_extract])
        return self._bits_to_data(payload_bits)

class AppendEngine:
    MAGIC_MARKER = b"!!STEGO_SECRET_SAUCE!!"
    def hide(self, cover_path, output_path, payload):
        with open(cover_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(f_in.read()); f_out.write(self.MAGIC_MARKER); f_out.write(payload)
    def extract(self, stego_path):
        with open(stego_path, 'rb') as f: data = f.read()
        marker_pos = data.rfind(self.MAGIC_MARKER)
        if marker_pos == -1: raise ValueError("Marker not found.")
        return data[marker_pos + len(self.MAGIC_MARKER):]

# --- Configuration and Main Functions for Flask to Call ---
CONFIG = {".png": "lsb", ".wav": "lsb"}
DEFAULT_STRATEGY = "append"

def hide_data(cover_path, secret_path, password, output_path, message=None):
    """Main function to hide data, callable by the server. Accepts an optional message."""
    ext = os.path.splitext(cover_path)[1].lower()
    strategy = CONFIG.get(ext, DEFAULT_STRATEGY)

    crypto = CryptoEngine(password)
    # --- Store message, filename, and file data ---
    original_filename = os.path.basename(secret_path)
    filename_bytes = original_filename.encode('utf-8')
    filename_len = len(filename_bytes)
    if filename_len > 255:
        raise ValueError("Filename too long to embed (max 255 bytes).")
    with open(secret_path, 'rb') as f:
        filedata = f.read()
    # Handle message
    if message is None:
        message_bytes = b''
    else:
        message_bytes = message.encode('utf-8')
    message_len = len(message_bytes)
    # Payload: [text_len (4 bytes)][text][filename_len (1 byte)][filename][filedata]
    payload = (
        message_len.to_bytes(4, 'big') +
        message_bytes +
        bytes([filename_len]) +
        filename_bytes +
        filedata
    )
    encrypted_payload = crypto.encrypt(payload)

    if strategy == "lsb":
        handler = PngHandler() if ext == '.png' else WavHandler()
        cover_data = handler.read(cover_path)
        stego_data = LsbEngine().hide(cover_data, encrypted_payload)
        handler.write(output_path, stego_data)
    else: # Append
        AppendEngine().hide(cover_path, output_path, encrypted_payload)


def extract_data(stego_path, password):
    """Main function to extract data, callable by the server. Returns (filedata, filename, message)."""
    ext = os.path.splitext(stego_path)[1].lower()
    strategy = CONFIG.get(ext, DEFAULT_STRATEGY)

    if strategy == "lsb":
        handler = PngHandler() if ext == '.png' else WavHandler()
        stego_data = handler.read(stego_path)
        encrypted_payload = LsbEngine().extract(stego_data)
    else: # Append
        encrypted_payload = AppendEngine().extract(stego_path)
    
    crypto = CryptoEngine(password)
    decrypted_payload = crypto.decrypt(encrypted_payload)
    if decrypted_payload is None or len(decrypted_payload) < 5:
        return None, None, None
    # Extract message
    message_len = int.from_bytes(decrypted_payload[:4], 'big')
    if len(decrypted_payload) < 4 + message_len + 1:
        return None, None, None
    message = decrypted_payload[4:4+message_len].decode('utf-8', errors='replace')
    # Extract filename
    filename_len = decrypted_payload[4+message_len]
    if len(decrypted_payload) < 4 + message_len + 1 + filename_len:
        return None, None, None
    filename = decrypted_payload[4+message_len+1:4+message_len+1+filename_len].decode('utf-8', errors='replace')
    filedata = decrypted_payload[4+message_len+1+filename_len:]
    return filedata, filename, message
