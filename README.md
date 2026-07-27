# Local PII Anonymization

A production-ready system for anonymizing sensitive data locally before sending to cloud LLMs, then de-anonymizing the response locally — ensuring **zero PII exposure to cloud models**.

## Features

- **Zero Cloud Exposure** - All PII detection, replacement, and mapping happens locally
- **Deterministic Tokens** - Same entity → same token (e.g., `PERSON_1`, `EMAIL_2`) for LLM context consistency
- **Encrypted Mapping** - AES-256-GCM + Argon2id passphrase-derived keys protect the token→original mapping
- **Perfect Round-trip** - Byte-for-byte restoration verified by test suite
- **Extensible Patterns** - Regex + spaCy NER + custom patterns
- **International Support** - E.164 phone numbers with country codes (+1, +91, +44, +68, +211, etc.) + US local formats

## Installation

```bash
pip install local-pii-anonymization
# For NER support:
pip install local-pii-anonymization[ner]
# Or install dependencies directly:
pip install cryptography argon2-cffi spacy
python -m spacy download en_core_web_sm  # for NER
```

## Quick Start

### CLI Usage

```bash
# Generate secure passphrase
anon gen-passphrase
# Output: mountain-river-sunset-forest-ocean

# Anonymize with NER (names, orgs, locations)
anon anonymize -i sensitive.txt -o safe.txt -m map.anonmap -p "your-passphrase" --ner
# Verify the output shows expected entity count (e.g., "Anonymized 475 entities")

# Send safe.txt to cloud LLM...

# De-anonymize response
anon deanonymize -i llm_response.txt -m map.anonmap -p "your-passphrase" -o final.txt
# Verify the output matches the original sensitive.txt
```

### Python API

```python
from anonymizer import Anonymizer, Deanonymizer

# Anonymize
anonymizer = Anonymizer(ner_enabled=True, ner_model="en_core_web_sm", passphrase="passphrase")
result = anonymizer.anonymize(text)
# result.anonymized_text - safe for cloud
# result.mapping - {token: original} for de-anonymization

# De-anonymize
deanonymizer = Deanonymizer(mapping=result.mapping, passphrase="passphrase")
restored = deanonymizer.deanonymize(result.anonymized_text)
assert restored == text  # Perfect round-trip
```

## Supported PII Types

See [SKILL.md](SKILL.md) for the complete list of supported PII types including:
- Network: email, phone, IP, MAC, etc.
- Auth/Secrets: API keys, tokens, passwords
- PII: SSN, credit card, address, passport, etc.
- Identifiers: UUID, ISBN, VIN
- Crypto: Bitcoin, Ethereum, Monero addresses
- NER (spaCy): PERSON, ORG, LOCATION, etc.

## Verification

Run the built-in test suite:

```bash
anon test
# Or with specific passphrase:
anon test -p "your-passphrase"
```

## Security Considerations

- **Passphrase strength** - Use generated passphrases (`anon gen-passphrase`) or strong custom ones
- **Mapping file protection** - `.anonmap` files are encrypted; never commit plaintext mappings
- **Memory safety** - Mappings decrypted only in memory, not logged
- **Token opacity** - Tokens like `PERSON_1` leak no semantic information
- **Frequency analysis** - Token frequency mirrors original entity frequency (acceptable for most LLM tasks)

## License

MIT

## Files

```
local-pii-anonymization/
├── anonymizer/                 # Python package
│   ├── __init__.py
│   ├── __main__.py             # Entry point
│   ├── anonymizer.py           # Core anonymization engine
│   ├── deanonymizer.py         # De-anonymization engine
│   ├── patterns.py             # 20+ built-in PII patterns
│   ├── crypto.py               # AES-256-GCM + Argon2id
│   └── cli.py                  # `anon` command
├── references/
│   ├── architecture.md         # Detailed design doc
│   └── session-anonymization-example.md
├── templates/
│   └── config.yaml.example     # Example configuration
├── scripts/
│   └── verify_roundtrip.py     # Round-trip verification script
└── pyproject.toml              # Package config
```
