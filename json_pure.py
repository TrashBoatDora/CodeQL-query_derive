#!/usr/bin/env python3

import json
import sys
import argparse
def dedupe_preserve_order(lst):
    seen = set()
    out = []
    for x in lst:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def main():
    ap = argparse.ArgumentParser(description="Deduplicate each list independently in a dict-of-lists JSON.")
    ap.add_argument("-i", "--input", help="Input JSON file (default: stdin)")
    ap.add_argument("-o", "--output", help="Output JSON file (default: stdout)")
    args = ap.parse_args()

    data = json.load(open(args.input, "r", encoding="utf-8")) if args.input else json.load(sys.stdin)

    if not isinstance(data, dict):
        raise SystemExit("Input must be a JSON object mapping strings to arrays.")

    result = {k: dedupe_preserve_order(v) for k, v in data.items()}

    dumped = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(dumped + "\n")
    else:
        sys.stdout.write(dumped + "\n")

if __name__ == "__main__":
    main()
