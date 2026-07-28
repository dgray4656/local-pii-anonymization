"""De-anonymization engine."""
import re
import json
from typing import Dict
from .crypto import encrypt_mapping, decrypt_mapping

class Deanonymizer:
    def __init__(self, mapping: str, passphrase: str = ""):
        """
        Initialize the deanonymizer.
        
        Args:
            mapping: Encrypted mapping string from anonymizer
            passphrase: Passphrase used to encrypt the mapping
        """
        self.passphrase = passphrase
        self.mapping = self._decrypt_mapping(mapping)
        self._sorted_tokens = sorted(self.mapping.keys(), key=len, reverse=True)
    
    def _decrypt_mapping(self, encrypted_mapping: str) -> Dict[str, str]:
        """Decrypt the mapping using the passphrase."""
        return decrypt_mapping(encrypted_mapping, self.passphrase)
    
    def deanonymize(self, text: str) -> str:
        """
        Restore original text by replacing tokens with original values.
        
        Args:
            text: Anonymized text with tokens
            
        Returns:
            De-anonymized text with original values restored
        """
        if not text or not self.mapping:
            return text
        
        result = text
        # Replace tokens in order of decreasing length to avoid prefix issues
        for token in self._sorted_tokens:
            original = self.mapping[token]
            # Use regex with word boundaries to prevent partial matches
            pattern = re.compile(r'(?<![A-Za-z0-9_])' + re.escape(token) + r'(?![A-Za-z0-9_])')
            result = pattern.sub(original, result)
        
        return result

# For CLI usage
if __name__ == "__main__":
    import sys
    print("This module is not meant to be run directly. Use the 'anon' command.")
    sys.exit(1)
