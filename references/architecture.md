# Local PII Anonymization Architecture

## Design Goals

1. **Zero Cloud PII Exposure** - All PII detection and replacement happens locally
2. **Deterministic Tokenization** - Same entity → same token for LLM context consistency
3. **Perfect Round-trip** - Original text fully restorable after cloud processing
4. **Secure Mapping Storage** - Encrypted mapping files with strong key derivation
5. **Extensible Pattern System** - Easy to add custom patterns for organization-specific IDs

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ANONYMIZATION PIPELINE                         │
└─────────────────────────────────────────────────────────────────────────┘

INPUT TEXT
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  PATTERN MATCHING (Parallel)                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ Regex       │  │ Regex       │  │ Regex       │  │ spaCy NER   │    │
│  │ Patterns    │  │ Patterns    │  │ Patterns    │  │ (optional)  │    │
│  │ (email,     │  │ (API keys,  │  │ (SSN,       │  │             │    │
│  │  phone, IP) │  │  JWT, etc)  │  │  address)   │  │ (PERSON,    │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  │  ORG, LOC)  │    │
└─────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  MATCH COLLECTION & DEDUPLICATION                                        │
│  • Collect all (start, end, text, pattern) tuples                        │
│  • Sort by start position, then by length (longest first)               │
│  • Filter overlaps: keep earliest start, longest match                  │
└─────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  TOKEN GENERATION & REPLACEMENT                                          │
│  • For each pattern type, maintain counter: EMAIL_1, EMAIL_2, ...       │
│  • Build result by replacing matches with tokens                        │
│  • Build mapping: {TOKEN: original_text}                                │
└─────────────────────────────────────────────────────────────────────────┘
    │
    ├──► ANONYMIZED TEXT (safe for cloud)
    │
    └──► MAPPING DICT ──► ENCRYPTION ──► .anonmap FILE
         (in-memory)      (AES-256-GCM + Argon2id)
```

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         DE-ANONYMIZATION PIPELINE                        │
└─────────────────────────────────────────────────────────────────────────┘

CLOUD RESPONSE + .anonmap + PASSPHRASE
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  DECRYPTION                                                              │
│  • Argon2id(passphrase, salt) → key                                     │
│  • AES-256-GCM(key, nonce, ciphertext) → plaintext JSON                 │
│  • Parse JSON → mapping dict                                            │
└─────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  TOKEN REPLACEMENT                                                       │
│  • Sort tokens by length (longest first) to avoid partial replacement   │
│  • For each token: text = text.replace(token, original)                 │
└─────────────────────────────────────────────────────────────────────────┘
    │
    ▼
RESTORED ORIGINAL TEXT
```

## Pattern System

### Pattern Structure

```python
@dataclass
class Pattern:
    name: str           # Unique identifier
    pattern: str        # Regex pattern
    token_prefix: str   # Token prefix (e.g., "EMAIL", "API_KEY")
    flags: int = 0      # Regex flags
    description: str = ""  # Human-readable description
```

### Categories

Patterns grouped by sensitivity category for selective application:

| Category | Patterns | Use Case |
|----------|----------|----------|
| `network` | email, phone, IP, MAC, URL creds, domains | Contact info, infrastructure |
| `auth` | API keys, JWT, SSH, AWS, GitHub, Slack, Discord, config secrets | Credentials, tokens |
| `pii` | SSN, credit card, address, ZIP, passport, DL, DOB | Personal identifiers |
| `crypto` | BTC, ETH, XMR addresses | Cryptocurrency |
| `identifiers` | UUID, ISBN, VIN | System identifiers |
| `all` | All of the above | Maximum coverage |

## Encryption Specification

### Key Derivation (Argon2id)

```
Parameters:
  - salt: 16 bytes (random per encryption)
  - memory: 1 MB (1024 KB) 
  - iterations: 3
  - parallelism: 1
  - hash length: 32 bytes (256-bit key)
```

### Encryption (AES-256-GCM)

```
Inputs:
  - key: 32 bytes (from Argon2id)
  - nonce: 12 bytes (random per encryption)
  - plaintext: UTF-8 JSON of mapping dict
  - associated_data: None

Output:
  - ciphertext: variable length
  - tag: 16 bytes (appended to ciphertext by cryptography library)

File Format (.anonmap):
  [salt:16][nonce:12][ciphertext+tag:variable]
```

### Decryption

```
1. Read file → split salt (16), nonce (12), ciphertext+tag (rest)
2. Argon2id(passphrase, salt) → key
3. AES-GCM(key, nonce, ciphertext+tag) → plaintext JSON
4. Parse JSON → mapping dict
```

## NER Integration Details

### spaCy Entity Types Mapped

| spaCy Label | Token Prefix | Notes |
|-------------|--------------|-------|
| PERSON | PERSON | Names of people |
| ORG | ORG | Companies, agencies |
| GPE | LOCATION | Countries, cities, states |
| LOC | LOCATION | Non-GPE locations |
| FAC | FACILITY | Buildings, airports |
| PRODUCT | PRODUCT | Products |
| EVENT | EVENT | Named events |
| WORK_OF_ART | WORK | Titles of works |
| LAW | LAW | Legal documents |
| LANGUAGE | LANGUAGE | Named languages |

### Excluded (High False Positive Rate)

- DATE, TIME, MONEY, PERCENT, QUANTITY, ORDINAL, CARDINAL, NORP

### False Positive Filters

Applied to all NER entities before tokenization:

1. **Length < 2** - Skip single characters
2. **Ends with `:`** - Skip labels like "API Key:"
3. **Uppercase label pattern** - Skip "SSN:", "CREDIT CARD:", "JWT:", etc.
4. **Confidence threshold** - Configurable minimum score (default 0.8)

## Token Generation

### Deterministic Counters

```python
_counters = defaultdict(int)

def _next_token(prefix: str) -> str:
    _counters[prefix] += 1
    return f"{prefix}_{_counters[prefix]}"
```

### Reset Behavior

Counters reset on each `anonymize()` call, ensuring consistent numbering within a single document but independent across documents.

## Overlap Resolution

When multiple patterns match overlapping text spans:

1. Sort by `start` ascending, then `end` descending (longest first)
2. Iterate, keeping match if `start >= last_end`
3. This prefers earlier matches, and among those starting at same position, the longest

Example: "john@company.com" matches both EMAIL and could match a custom pattern
- EMAIL starts at 0, ends at 16
- Custom might start at 5, end at 16
- EMAIL wins (earlier start)

## Performance Characteristics

| Operation | Complexity | Typical Time (1KB text) |
|-----------|------------|------------------------|
| Pattern compilation | O(n) patterns | ~1ms (once, cached) |
| Regex matching | O(text × patterns) | ~2-5ms |
| NER (en_core_web_sm) | O(text) | ~15-30ms |
| Replacement | O(matches × text) | <1ms |
| Encryption | O(mapping size) | ~5-10ms |
| Decryption | O(mapping size) | ~5-10ms |

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Cloud LLM sees PII | Only tokens leave machine |
| Mapping file stolen | AES-256-GCM + Argon2id |
| Passphrase brute-forced | Argon2id memory-hard KDF |
| Token frequency analysis | Acceptable for most LLM tasks |
| Partial replacement bugs | Length-sorted replacement |
| NER false positives | Multi-layer filtering |

### Best Practices

1. **Generate passphrases** with `anon gen-passphrase` (5-word diceware)
2. **Rotate mappings** per conversation/session
3. **Don't reuse passphrases** across different data sets
4. **Store .anonmap separately** from anonymized text
5. **Verify round-trip** before sending to cloud: `anon test`

## Extending the System

### Adding a Pattern Category

```python
# In patterns.py
PATTERN_CATEGORIES["my_category"] = ["pattern1", "pattern2"]
```

### Custom Token Prefix Logic

Modify `_next_token()` in `anonymizer.py` for different token formats:
- `PREFIX_N` (current)
- `PREFIX-N`
- `PREFIX[N]`
- UUID-based tokens

### Alternative NER Backends

Replace `_get_nlp()` and NER loop in `anonymize()` to use:
- Stanza
- Flair
- Transformers (BERT-based NER)
- Cloud NER APIs (for non-sensitive pre-filtering)

## Testing Strategy

### Unit Tests (Per Component)

- Pattern compilation and matching
- Overlap resolution
- Token generation determinism
- Encryption/decryption round-trip
- NER false positive filtering

### Integration Tests

- Full anonymize → deanonymize round-trip
- Encrypted mapping save/load
- CLI command execution
- Category filtering
- Custom pattern handling

### Property-Based Tests

- Round-trip on random text with injected PII
- Mapping size proportional to unique entities
- Token format consistency

## Future Enhancements

- [ ] Structured data support (JSON, CSV, XML field-level anonymization)
- [ ] Streaming mode for large files
- [ ] Differential privacy noise injection
- [ ] Multi-language NER models
- [ ] Token format plugins
- [ ] Audit logging (optional)
- [ ] Policy engine (per-field rules)