"""Built-in PII detection patterns."""
import re
from typing import Dict, List

# Pattern structure: {"key": str, "pattern": str, "prefix": str, "description": str}
BUILTIN_PATTERNS = [
    # Network
    {"key": "email", "pattern": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
     "prefix": "EMAIL", "description": "Email addresses"},
    {"key": "phone", "pattern": r'(?:\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b', 
     "prefix": "PHONE", "description": "Phone numbers"},
    {"key": "ip", "pattern": r'\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', 
     "prefix": "IP", "description": "IPv4 and IPv6 addresses"},
    {"key": "mac", "pattern": r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b', 
     "prefix": "MAC", "description": "MAC addresses"},
    {"key": "url_creds", "pattern": r'https?://[^\s]+:[^\s]+@[^\s]+', 
     "prefix": "URL_CREDS", "description": "URLs with embedded credentials"},
    {"key": "domain", "pattern": r'(?<!@)(?:\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)(?!@)', 
     "prefix": "DOMAIN", "description": "Domain names"},
    
    # Auth/Secrets
    {"key": "openai_key", "pattern": r'\bsk-[a-zA-Z0-9]{20,}\b', 
     "prefix": "OPENAI_KEY", "description": "OpenAI API keys"},
    {"key": "anthropic_key", "pattern": r'\bsk-ant-[a-zA-Z0-9]{20,}\b', 
     "prefix": "ANTHROPIC_KEY", "description": "Anthropic API keys"},
    {"key": "aws_key", "pattern": r'\b(A3T[A-Z0-9]|AKIA|AGOA|AIDA|ANOA|ANVA|ASIA)[A-Z0-9]{16}\b', 
     "prefix": "AWS_KEY", "description": "AWS access keys"},
    {"key": "github_token", "pattern": r'\bghp_[a-zA-Z0-9]{36}|\bgho_[a-zA-Z0-9]{36}|\bghu_[a-zA-Z0-9]{36}|\bghs_[a-zA-Z0-9]{36}|\bghr_[a-zA-Z0-9]{36}\b', 
     "prefix": "GITHUB_TOKEN", "description": "GitHub personal access tokens"},
    {"key": "slack_token", "pattern": r'\bxox[baprs]-([a-zA-Z0-9-]+)\b', 
     "prefix": "SLACK_TOKEN", "description": "Slack tokens"},
    {"key": "discord_token", "pattern": r'\b[MN][a-zA-Z0-9_-]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}\b', 
     "prefix": "DISCORD_TOKEN", "description": "Discord bot tokens"},
    {"key": "jwt", "pattern": r'\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b', 
     "prefix": "JWT", "description": "JSON Web Tokens"},
    {"key": "config_secret", "pattern": r'\b(password|secret|key|token)[:=]\s*[^\s\n]+\b', 
     "prefix": "CONFIG_SECRET", "description": "Configuration secrets (password, secret, etc.)"},
    
    # PII
    {"key": "ssn", "pattern": r'\b\d{3}-?\d{2}-?\d{4}\b', 
     "prefix": "SSN", "description": "Social Security Numbers"},
    {"key": "credit_card", "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b', 
     "prefix": "CREDIT_CARD", "description": "Credit card numbers"},
    {"key": "address", "pattern": r'\b\d{1,5}\s+[A-Za-z0-9\s,.#]+(?:Avenue|Lane|Road|Boulevard|Drive|Street|Ave|Ln|Rd|Blvd|Dr|St)\s*[A-Za-z0-9\s,.#]*\b', 
     "prefix": "ADDRESS", "description": "Street addresses"},
    {"key": "zip", "pattern": r'\b\d{5}(?:-[0-9]{4})?\b', 
     "prefix": "ZIP", "description": "ZIP codes"},
    {"key": "passport", "pattern": r'\b[A-Za-z]{1,2}\d{6,9}\b', 
     "prefix": "PASSPORT", "description": "Passport numbers"},
    {"key": "dl", "pattern": r'\b[A-Za-z]\d{1,8}\b(?!@)', 
     "prefix": "DL", "description": "Driver's license numbers"},
    {"key": "dob", "pattern": r'\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b', 
     "prefix": "DOB", "description": "Date of birth"},
    
    # Identifiers
    {"key": "uuid", "pattern": r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', 
     "prefix": "UUID", "description": "UUIDs"},
    {"key": "isbn", "pattern": r'\b(?:ISBN(?:-13)?:?\s*)?(?:97[89])[0-9]{10}\b|\b(?:ISBN-10:?\s*)?[0-9]{9}[0-9X]\b', 
     "prefix": "ISBN", "description": "ISBN numbers"},
    {"key": "vin", "pattern": r'\b[A-HJ-NPR-Z\d]{11}\d[A-HJ-NPR-Z\d][\d]{2}[A-HJ-NPR-Z\d]{3}\d{4}\b', 
     "prefix": "VIN", "description": "Vehicle Identification Numbers"},
    
    # Crypto
    {"key": "btc_address", "pattern": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[ac-hj-np-z02-9]{11,71}\b', 
     "prefix": "BTC_ADDRESS", "description": "Bitcoin addresses"},
    {"key": "eth_address", "pattern": r'\b0x[a-fA-F0-9]{40}\b', 
     "prefix": "ETH_ADDRESS", "description": "Ethereum addresses"},
    {"key": "xmr_address", "pattern": r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', 
     "prefix": "XMR_ADDRESS", "description": "Monero addresses"},
]

def create_custom_pattern(name: str, pattern: str, prefix: str, description: str = "") -> Dict:
    """
    Create a custom pattern for anonymization.
    
    Args:
        name: Internal name for the pattern
        pattern: Regular expression pattern
        prefix: Token prefix to use (e.g., "EMP_ID")
        description: Human-readable description
        
    Returns:
        Dictionary suitable for adding to patterns list
    """
    return {
        "key": name,
        "pattern": pattern,
        "prefix": prefix,
        "description": description
    }
