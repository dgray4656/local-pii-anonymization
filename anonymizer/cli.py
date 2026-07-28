import argparse
import sys
import os

from . import __version__
from . import Anonymizer, Deanonymizer


def gen_passphrase():
    """Generate a secure passphrase for encryption."""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(alphabet) for _ in range(32))


def cmd_gen_passphrase(args):
    """Handle the gen-passphrase subcommand."""
    print(gen_passphrase())


def cmd_anonymize(args):
    """Handle the anonymize subcommand."""
    # Read input
    if args.input:
        with open(args.input, 'r', encoding='utf-8', newline='') as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    # Create anonymizer
    anonymizer = Anonymizer(
        ner_enabled=args.ner,
        passphrase=args.passphrase or "",
        categories=args.category,
    )

    # Anonymize
    result = anonymizer.anonymize(text)

    # Write output
    if args.output:
        with open(args.output, 'w', encoding='utf-8', newline='') as f:
            f.write(result["anonymized_text"])
    else:
        sys.stdout.write(result["anonymized_text"])

    if args.verbose:
        print(f"Anonymized {len(result['mapping'])} entities", file=sys.stderr)


def cmd_deanonymize(args):
    """Handle the deanonymize subcommand."""
    # Read input
    if args.input:
        with open(args.input, 'r', encoding='utf-8', newline='') as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    # Read mapping
    with open(args.mapping, 'r', encoding='utf-8', newline='') as f:
        mapping = f.read()

    # Create deanonymizer
    deanonymizer = Deanonymizer(mapping=mapping, passphrase=args.passphrase or "")

    # De-anonymize
    result = deanonymizer.deanonymize(text)

    # Write output
    if args.output:
        with open(args.output, 'w', encoding='utf-8', newline='') as f:
            f.write(result)
    else:
        sys.stdout.write(result)

    if args.verbose:
        print("De-anonymization complete", file=sys.stderr)


def cmd_test(args):
    """Run the test suite."""
    # Simple round-trip test
    test_cases = [
        "Contact John Doe at john.doe@example.com or (555) 123-4567",
        "SSN: [SSN], Credit Card: [CREDIT_CARD]",
        "API key: sk-abc...3456",
        "Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "Ethereum: 0x742d35Cc6634C0532925a3b8D4C0532950532950",
    ]

    passphrase = args.passphrase if args.passphrase else gen_passphrase()
    print(f"Using passphrase: {passphrase}")

    all_passed = True
    for i, test_case in enumerate(test_cases):
        try:
            # Anonymize
            anonymizer = Anonymizer(ner_enabled=False, passphrase=passphrase)
            anon_result = anonymizer.anonymize(test_case)

            # De-anonymize
            deanonymizer = Deanonymizer(mapping=anon_result["mapping"], passphrase=passphrase)
            restored = deanonymizer.deanonymize(anon_result["anonymized_text"])

            if restored == test_case:
                print(f"Test {i+1}: PASSED")
            else:
                print(f"Test {i+1}: FAILED")
                print(f"  Original:    {repr(test_case)}")
                print(f"  Anonymized:  {repr(anon_result['anonymized_text'])}")
                print(f"  Restored:    {repr(restored)}")
                all_passed = False
        except Exception as e:
            print(f"Test {i+1}: ERROR - {e}")
            all_passed = False

    if all_passed:
        print("\nAll tests passed!")
        sys.exit(0)
    else:
        print("\nSome tests failed!")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Local PII Anonymization Tool")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-p", "--passphrase", help="Passphrase for encryption")

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # gen-passphrase
    gen_parser = subparsers.add_parser('gen-passphrase', help='Generate a secure passphrase')
    gen_parser.set_defaults(func=cmd_gen_passphrase)

    # anonymize
    anon_parser = subparsers.add_parser('anonymize', help='Anonymize text')
    anon_parser.add_argument('-i', '--input', help='Input file (default: stdin)')
    anon_parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    anon_parser.add_argument('-m', '--mapping', required=True, help='Mapping file')
    anon_parser.add_argument('--ner', action='store_true', help='Enable NER (requires spaCy)')
    anon_parser.add_argument('--category', action='append',
                            choices=['network', 'auth', 'pii', 'crypto', 'identifiers', 'all'],
                            help='Categories to enable (can be used multiple times)')
    anon_parser.set_defaults(func=cmd_anonymize)

    # deanonymize
    deanon_parser = subparsers.add_parser('deanonymize', help='De-anonymize text')
    deanon_parser.add_argument('-i', '--input', help='Input file (default: stdin)')
    deanon_parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    deanon_parser.add_argument('-m', '--mapping', required=True, help='Mapping file')
    deanon_parser.set_defaults(func=cmd_deanonymize)

    # test
    test_parser = subparsers.add_parser('test', help='Run test suite')
    test_parser.add_argument('-p', '--passphrase', help='Passphrase for tests')
    test_parser.set_defaults(func=cmd_test)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
