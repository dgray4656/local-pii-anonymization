"""Encryption utilities for mapping protection."""
import os
import json
from base64 import b64encode, b64decode
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def encrypt_mapping(mapping: dict, passphrase: str) -> str:
    """
    Encrypt a mapping dictionary using Argon2id + AES-256-GCM.
    
    Args:
        mapping: Dictionary mapping tokens to original values
        passphrase: Passphrase for key derivation
        
    Returns:
        Base64-encoded encrypted mapping (nonce + ciphertext + tag)
    """
    if not passphrase:
        # Return JSON if no passphrase (for testing)
        return b64encode(json.dumps(mapping).encode('utf-8')).decode('utf-8')
    
    # Derive key using Argon2id
    salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        length=32,  # 256 bits
        memory_cost=1024,  # 1 MB
        iterations=3,
        lanes=1
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96 bits for GCM
    plaintext = json.dumps(mapping).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Combine salt + nonce + ciphertext and encode
    combined = salt + nonce + ciphertext
    return b64encode(combined).decode('utf-8')

def decrypt_mapping(encoded_data: str, passphrase: str) -> dict:
    """
    Decrypt a mapping dictionary using Argon2id + AES-256-GCM.
    
    Args:
        encrypted_data: Base64-encoded encrypted mapping
        passphrase: Passphrase used for encryption
        
    Returns:
        Dictionary mapping tokens to original values
    """
    if not passphrase:
        # Try to parse as plain JSON first (for --no-encrypt mode)
        try:
            return json.loads(encoded_data)
        except json.JSONDecodeError:
            pass
        # Fall back to base64 encoded JSON (legacy format)
        try:
            return json.loads(b64decode(encoded_data).decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid mapping data")
    
    # Decode
    try:
        combined = b64decode(encoded_data)
    except Exception:
        raise ValueError("Invalid base64 encoding")
    
    if len(combined) < 28:  # salt(16) + nonce(12)
        raise ValueError("Encrypted data too short")
    
    # Extract components
    salt = combined[:16]
    nonce = combined[16:28]
    ciphertext = combined[28:]
    
    # Derive key
    kdf = Argon2id(
        salt=salt,
        length=32,
        memory_cost=1024,
        iterations=3,
        lanes=1
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    
    # Decrypt
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# For testing
if __name__ == "__main__":
    # Simple test
    test_mapping = {"TEST_1": "original_value", "TEST_2": "another_value"}
    encrypted = encrypt_mapping(test_mapping, "test-passphrase")
    decrypted = decrypt_mapping(encrypted, "test-passphrase")
    assert decrypted == test_mapping
    print("Crypto test passed!")
