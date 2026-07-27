#!/usr/bin/env python3
"""
Round-trip verification script for local-pii-anonymization.
Tests anonymize → deanonymize cycle with various PII types.
"""

import sys
import tempfile
from pathlib import Path

# Add the anonymizer package to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "anonymizer"))

from anonymizer import Anonymizer, Deanonymizer


# Test cases covering all pattern categories - using obviously fake/test values
TEST_CASES = [
    # Network
    ("Contact: alice@example.com", "email"),
    ("Call +1-555-123-4567", "phone"),
    ("Server at 192.168.1.1", "ipv4"),
    ("IPv6: 2001:db8::1", "ipv6"),
    ("MAC: aa:bb:cc:dd:ee:ff", "mac"),
    ("URL: https://user:pass@internal.site", "url_credentials"),

    # Auth/Secrets - using obviously fake/test values
    ("OpenAI: sk-fake111111111111111111111111111111", "openai_key"),
    ("Anthropic: sk-ant-fake011111111111111111111111111111", "anthropic_key"),
    ("Generic: ak-fake111111111111111111111111111111", "generic_api_key"),
    ("AWS: AKIAFAKE1111111111", "aws_access_key"),
    ("AWS Secret: fakescretstringfortesting1234567890", "aws_secret_key"),
    ("GitHub: ghp_fake11111111111111111111111111111111", "github_token"),
    ("JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJZZZZZIiwibmFtZSI6IkZBWSBGVUkiLCJpYXQiOjE3MTcyMzUyMDB9.signature", "jwt"),
    ("Slack: xoxb-fake-111-1111111-1111111-111111111111", "slack_token"),
    ("Discord: FAKE_DISCORD_TOKEN_1234567890", "discord_token"),
    ("Config: password=fake-password-123", "config_secret"),

    # PII
    ("SSN: [SSN]", "ssn"),
    ("Card: 4111111111111111", "credit_card"),
    ("Address: 123 Main Street, Springfield, IL 62704", "address"),

    # Identifiers
    ("UUID: 550e8400-e29b-41d4-a716-446655440000", "uuid"),

    # Crypto
    ("BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc_address"),
    ("Ethereum: 0x742d35Cc6634C0532925a3b8D4C0532950532950", "eth_address"),
    ("Monero: 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A", "xmr_address"),
]


def run_regex_tests(passphrase):
    """Test regex pattern matching."""
    print("  Testing regex patterns...")
    anonymizer = Anonymizer(ner_enabled=False, passphrase=passphrase)
    deanonymizer = Deanonymizer(mapping="", passphrase=passphrase)
    
    all_passed = True
    for text, _ in TEST_CASES:
        try:
            # Anonymize
            anon_result = anonymizer.anonymize(text)
            
            # De-anonymize
            deanonymizer.mapping = anon_result["mapping"]
            restored = deanonymizer.deanonymize(anon_result["anonymized_text"])
            
            if restored != text:
                print(f"    ❌ FAIL: {text}")
                print(f"      Expected: {text}")
                print(f"      Got:      {restored}")
                all_passed = False
        except Exception as e:
            print(f"    ❌ ERROR: {text} - {e}")
            all_passed = False
    
    return all_passed


def run_encrypted_mapping_test(passphrase):
    """Test encrypted mapping functionality."""
    print("  Testing encrypted mapping...")
    try:
        # Test with passphrase
        anonymizer = Anonymizer(ner_enabled=False, passphrase=passphrase)
        test_text = "Contact: test@example.com"
        anon_result = anonymizer.anonymize(test_text)
        
        # Check that mapping is encrypted (not plain JSON)
        mapping = anon_result["mapping"]
        assert isinstance(mapping, str)
        assert not mapping.startswith('{')  # Should be base64 encrypted
        
        # Test de-anonymization
        deanonymizer = Deanonymizer(mapping=mapping, passphrase=passphrase)
        restored = deanonymizer.deanonymize(anon_result["anonymized_text"])
        assert restored == test_text
        
        # Test without passphrase
        anonymizer_no_pass = Anonymizer(ner_enabled=False, passphrase="")
        anon_result_no_pass = anonymizer_no_pass.anonymize(test_text)
        mapping_no_pass = anon_result_no_pass["mapping"]
        assert mapping_no_pass.startswith('{')  # Should be plain JSON
        
        return True
    except Exception as e:
        print(f"    ❌ ERROR: {e}")
        return False


def run_category_filtering_tests(passphrase):
    """Test category filtering."""
    print("  Testing category filtering...")
    try:
        # Test with only network category
        anonymizer = Anonymizer(
            ner_enabled=False, 
            passphrase=passphrase,
            categories=["network"]
        )
        test_text = "Email: test@example.com Phone: 555-123-4567 SSN: [SSN]"
        anon_result = anonymizer.anonymize(test_text)
        
        # Should only anonymize email and phone, not SSN
        anonymized = anon_result["anonymized_text"]
        assert "test@example.com" not in anonymized
        assert "555-123-4567" not in anonymized
        assert "[SSN]" in anonymized  # Should NOT be anonymized
        
        return True
    except Exception as e:
        print(f"    ❌ ERROR: {e}")
        return False


def run_custom_pattern_test(passphrase):
    """Test custom patterns."""
    print("  Testing custom patterns...")
    try:
        from anonymizer.patterns import create_custom_pattern
        
        custom_patterns = [
            create_custom_pattern("employee_id", r"EMP-\d{6}", "EMP_ID"),
            create_custom_pattern("ticket_id", r"TKT-\d{8}", "TICKET")
        ]
        
        anonymizer = Anonymizer(
            ner_enabled=False, 
            passphrase=passphrase,
            patterns=custom_patterns
        )
        
        test_text = "Employee: EMP-123456 Ticket: TKT-87654321"
        anon_result = anonymizer.anonymize(test_text)
        
        # De-anonymize
        deanonymizer = Deanonymizer(mapping=anon_result["mapping"], passphrase=passphrase)
        restored = deanonymizer.deanonymize(anon_result["anonymized_text"])
        
        assert restored == test_text
        return True
    except Exception as e:
        print(f"    ❌ ERROR: {e}")
        return False


def run_ner_tests(passphrase):
    """Test NER functionality."""
    print("  Testing NER...")
    try:
        # Try to load spaCy model
        import spacy
        try:
            nlp = spacy.load("en_core_web_sm")
        except OSError:
            print("    ⚠️  spaCy model not available, skipping NER tests")
            return True
        
        anonymizer = Anonymizer(
            ner_enabled=True, 
            ner_model="en_core_web_sm",
            passphrase=passphrase
        )
        
        test_text = "John Doe works at Microsoft in Seattle."
        anon_result = anonymizer.anonymize(test_text)
        
        # De-anonymize
        deanonymizer = Deanonymizer(mapping=anon_result["mapping"], passphrase=passphrase)
        restored = deanonymizer.deanonymize(anon_result["anonymized_text"])
        
        assert restored == test_text
        return True
    except ImportError:
        print("    ⚠️  spaCy not installed, skipping NER tests")
        return True
    except Exception as e:
        print(f"    ❌ ERROR: {e}")
        return False


def main():
    """Run all verification tests."""
    print("=" * 60)
    print("Local PII Anonymization - Round-trip Verification")
    print("=" * 60)
    
    passphrase = "test-passphrase-123"
    
    results = []
    results.append(("Regex Patterns", run_regex_tests(passphrase)))
    results.append(("Encrypted Mapping", run_encrypted_mapping_test(passphrase)))
    results.append(("Category Filtering", run_category_filtering_tests(passphrase)))
    results.append(("Custom Patterns", run_custom_pattern_test(passphrase)))
    results.append(("NER", run_ner_tests(passphrase)))
    
    print("
" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for name, passed in results:
        status = "✓ PASS" if passed else "❌ FAIL"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False
    
    print("=" * 60)
    
    if all_passed:
        print("ALL TESTS PASSED ✓")
        return 0
    else:
        print("SOME TESTS FAILED ❌")
        return 1


if __name__ == "__main__":
    sys.exit(main())
