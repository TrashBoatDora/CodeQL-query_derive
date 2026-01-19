#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Download Python repositories from repos_python.csv into python_query_output folder
"""

import os
import csv
import subprocess
from pathlib import Path

# Constants
CSV_FILE = "repos_python.csv"
OUTPUT_DIR = "projects/python"  # Changed to match batch_autoql_from_csv.sh structure

def main():
    # Get the script directory
    script_dir = Path(__file__).parent
    csv_path = script_dir / CSV_FILE
    output_path = script_dir / OUTPUT_DIR
    
    # Create output directory if it doesn't exist
    output_path.mkdir(parents=True, exist_ok=True)
    
    print(f"Reading repositories from: {csv_path}")
    print(f"Downloading to: {output_path}")
    print("-" * 80)
    
    # Read CSV file with error handling for encoding
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            repos = list(reader)
    except UnicodeDecodeError:
        # Try with latin-1 encoding if utf-8 fails
        with open(csv_path, 'r', encoding='latin-1') as f:
            reader = csv.DictReader(f)
            repos = list(reader)
    
    total = len(repos)
    print(f"Found {total} repositories to download\n")
    
    success_count = 0
    skip_count = 0
    fail_count = 0
    
    for idx, repo in enumerate(repos, 1):
        name = repo['name']
        clone_url = repo['clone_url']
        
        # Extract repo folder name (e.g., "owner/repo" -> "repo")
        repo_folder = name.split('/')[-1]
        repo_path = output_path / repo_folder
        
        print(f"[{idx}/{total}] {name}")
        
        # Check if already exists
        if repo_path.exists():
            print(f"  ✓ Already exists, skipping")
            skip_count += 1
            continue
        
        # Clone repository
        try:
            print(f"  Cloning from {clone_url}...")
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', clone_url, str(repo_path)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                print(f"  ✓ Successfully cloned")
                success_count += 1
            else:
                print(f"  ✗ Failed to clone: {result.stderr}")
                fail_count += 1
                
        except subprocess.TimeoutExpired:
            print(f"  ✗ Timeout (5 minutes exceeded)")
            fail_count += 1
        except Exception as e:
            print(f"  ✗ Error: {e}")
            fail_count += 1
        
        print()
    
    # Summary
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total repositories: {total}")
    print(f"Successfully cloned: {success_count}")
    print(f"Already existed: {skip_count}")
    print(f"Failed: {fail_count}")
    print("=" * 80)

if __name__ == "__main__":
    main()
