"""Core anonymization engine with regex patterns and optional NER."""
import re
import json
from typing import Dict, List, Tuple, Optional
from .patterns import BUILTIN_PATTERNS, create_custom_pattern
from .crypto import encrypt_mapping, decrypt_mapping

class Anonymizer:
    def __init__(self, ner_enabled: bool = False, ner_model: str = "en_core_web_sm", 
                 ner_confidence: float = 0.8, passphrase: str = "", 
                 patterns: Optional[List[Dict]] = None,
                 categories: Optional[List[str]] = None):
        """
        Initialize the anonymizer.
        
        Args:
            ner_enabled: Whether to use spaCy NER
            ner_model: spaCy model to use
            ner_confidence: Minimum confidence threshold for NER
            passphrase: Passphrase for encrypting the mapping
            patterns: Custom patterns to add
            categories: List of categories to enable (network, auth, pii, crypto, identifiers, all)
        """
        self.ner_enabled = ner_enabled
        self.ner_model = ner_model
        self.ner_confidence = ner_confidence
        self.passphrase = passphrase
        self.patterns = []
        self.categories = categories or ["all"]
        
        # Load builtin patterns
        self._load_patterns()
        
        # Add custom patterns if provided
        if patterns:
            self.patterns.extend(patterns)
            
        # Initialize counters for deterministic tokens
        self._counters: Dict[str, int] = {}
        self._token_mapping: Dict[str, str] = {}
        
        # Initialize NER if enabled
        if self.ner_enabled:
            try:
                import spacy
                self.nlp = spacy.load(ner_model)
            except ImportError:
                raise ImportError("spacy not installed. Install with: pip install spacy")
            except OSError:
                raise OSError(f"spacy model '{ner_model}' not found. Download with: python -m spacy download {ner_model}")
    
    def _load_patterns(self):
        """Load patterns based on selected categories."""
        if "all" in self.categories:
            self.patterns.extend(BUILTIN_PATTERNS)
        else:
            category_map = {
                "network": ["email", "phone", "ip", "mac", "url_creds", "domain"],
                "auth": ["openai_key", "anthropic_key", "aws_key", "github_token", 
                        "slack_token", "discord_token", "jwt", "config_secret"],
                "pii": ["ssn", "credit_card", "address", "zip", "passport", "dl", "dob"],
                "crypto": ["btc_address", "eth_address", "xmr_address"],
                "identifiers": ["uuid", "isbn", "vin"]
            }
            
            for category in self.categories:
                if category in category_map:
                    for pattern_key in category_map[category]:
                        if pattern_key in BUILTIN_PATTERNS_BY_KEY:
                            self.patterns.append(BUILTIN_PATTERNS_BY_KEY[pattern_key])
    
    def _get_next_token(self, prefix: str) -> str:
        """Get the next deterministic token for a given prefix."""
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        return f"{prefix}_{self._counters[prefix]}"
    
    def anonymize(self, text: str) -> dict:
        """
        Anonymize text by replacing PII with deterministic tokens.
        
        Args:
            text: Input text to anonymize
            
        Returns:
            Dictionary with:
                - anonymized_text: Text with PII replaced by tokens
                - mapping: Dictionary mapping tokens to original values
        """
        if not text:
            return {"anonymized_text": text, "mapping": {}}
        
        # Reset state for this anonymization
        self._counters = {}
        self._token_mapping = {}
        
        # Apply regex patterns
        anonymized = text
        matches_found = []
        
        for pattern_info in self.patterns:
            regex = re.compile(pattern_info["pattern"], re.IGNORECASE)
            for match in regex.finditer(text):
                original = match.group(0)
                # Skip if we've already processed this exact match
                if any(m["original"] == original and m["start"] == match.start() 
                       for m in matches_found):
                    continue
                # Skip if this match is entirely inside an already-matched region
                if any(m["start"] <= match.start() and match.end() <= m["end"]
                       for m in matches_found):
                    continue

                
                token = self._get_next_token(pattern_info["prefix"])
                self._token_mapping[token] = original
                matches_found.append({
                    "original": original,
                    "token": token,
                    "start": match.start(),
                    "end": match.end()
                })
        
        # Replace matches in reverse order to maintain positions
        anonymized = text
        for match in sorted(matches_found, key=lambda x: x["start"], reverse=True):
            anonymized = anonymized[:match["start"]] + match["token"] + anonymized[match["end"]:]
        
        # Apply NER if enabled
        if self.ner_enabled:
            anonymized, ner_matches = self._apply_ner(anonymized)
            matches_found.extend(ner_matches)
        
        # Encrypt the mapping
        encrypted_mapping = encrypt_mapping(self._token_mapping, self.passphrase)
        
        return {
            "anonymized_text": anonymized,
            "mapping": encrypted_mapping
        }
    
    def _apply_ner(self, text: str) -> tuple:
        """Apply spaCy NER to the text."""
        if not hasattr(self, 'nlp'):
            return text, []
        
        doc = self.nlp(text)
        matches_found = []
        
        # Map spaCy labels to our prefixes
        label_map = {
            "PERSON": "PERSON",
            "ORG": "ORG",
            "GPE": "LOCATION",
            "LOC": "LOCATION",
            "FAC": "FACILITY",
            "PRODUCT": "PRODUCT",
            "EVENT": "EVENT",
            "WORK_OF_ART": "WORK",
            "LAW": "LAW",
            "LANGUAGE": "LANGUAGE",
            "DATE": "DATE",
            "TIME": "TIME",
            "MONEY": "MONEY",
            "PERCENT": "PERCENT"
        }
        
        for ent in doc.ents:
            # Skip if confidence is too low
            if hasattr(ent, '_') and hasattr(ent._, 'confidence'):
                if ent._.confidence < self.ner_confidence:
                    continue
            
            # Skip entities ending with ':' (often labels)
            if ent.text.strip().endswith(':'):
                continue
                
            # Skip known false positives
            false_positives = {"SSN", "API KEY", "CREDIT CARD", "JWT", "AWS KEY"}
            if ent.text.upper() in false_positives:
                continue
                
            # Skip if too short
            if len(ent.text.strip()) < 2:
                continue
            
            prefix = label_map.get(ent.label_)
            if prefix:
                original = ent.text
                # Check if we already have a token for this exact text
                existing_token = None
                for token, orig in self._token_mapping.items():
                    if orig == original and token.startswith(prefix + "_"):
                        existing_token = token
                        break
                
                if existing_token is None:
                    token = self._get_next_token(prefix)
                    self._token_mapping[token] = original
                else:
                    token = existing_token
                
                matches_found.append({
                    "original": original,
                    "token": token,
                    "start": ent.start_char,
                    "end": ent.end_char
                })
        
        # Replace NER matches in reverse order
        anonymized = text
        for match in sorted(matches_found, key=lambda x: x["start"], reverse=True):
            anonymized = anonymized[:match["start"]] + match["token"] + anonymized[match["end"]:]
        
        return anonymized, matches_found

# Build lookup dictionary for patterns
BUILTIN_PATTERNS_BY_KEY = {p["key"]: p for p in BUILTIN_PATTERNS}
