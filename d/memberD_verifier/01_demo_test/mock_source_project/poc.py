#!/usr/bin/env python3
import sys

print("triggering mock source/API misuse path")
print("AddressSanitizer: SEGV on unknown address")
print("SUMMARY: AddressSanitizer: null pointer dereference")
sys.exit(1)
