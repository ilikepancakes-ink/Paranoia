#!/usr/bin/env python3

import os
import sys
import hashlib
import time
import threading
import platform
import subprocess
from pathlib import Path

# Suspicious file patterns
SUSPICIOUS_PATTERNS = [
    'rootkit',
    'backdoor',
    'trojan',
    'virus',
    'malware',
    'keylogger',
    'spyware',
    'ransomware',
    '.hidden',
    'temp.exe',
    'system32.dll',  # suspicious if not in Windows
]

def load_linux_malware_hashes():
    """Load Linux malware hashes from the SHA256 file for enhanced Linux scanning."""
    try:
        linux_hashes = set()
        with open('linuxscan/full_sha256.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Add the hash to the set
                linux_hashes.add(line.lower())
        return linux_hashes
    except Exception as e:
        print(f"Warning: Could not load Linux malware hashes: {e}")
        return set()

def load_windows_vulnerabilities():
    """Load Windows vulnerabilities from CSV for enhanced Windows scanning."""
    try:
        import csv
        with open('windowsscan/known_exploited_vulnerabilities.csv', 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)  # Skip header row
            vulnerabilities = []
            for row in reader:
                if len(row) >= 6:  # Ensure we have enough fields
                    cve_id = row[0]
                    vendor = row[1]
                    product = row[2]
                    vuln_name = row[3]
                    short_desc = row[5]
                    # Add to patterns to check against
                    vulnerabilities.extend([cve_id, vendor, product, vuln_name, short_desc])
            return vulnerabilities
    except Exception as e:
        print(f"Warning: Could not load Windows vulnerabilities CSV: {e}")
        return []

def read_logo():
    try:
        with open('logo.txt', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "PARANOIA SCANNER"

def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')

def loading_animation(duration):
    logo = read_logo()
    clear_screen()
    print(logo)
    print("\nLoading Paranoia Scanner...")
    for i in range(duration * 10):
        progress = int((i / (duration * 10 - 1)) * 100)
        bar = "█" * (progress // 5) + "-" * ((100 - progress) // 5)
        print(f"\r[{bar}] {progress}%", end='', flush=True)
        time.sleep(0.1)
    print("\n")

def get_user_choice():
    while True:
        choice = input("Select option (1 to scan, 2 to stop): ").strip()
        if choice == "1":
            return "scan"
        elif choice == "2":
            return "stop"
        print("Invalid choice. Please enter 1 or 2.")

def calculate_file_hash(filepath):
    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, IOError):
        return None

def is_suspicious_file(filepath, current_os, linux_hashes=None):
    # Check file extension and name patterns
    if any(pattern.lower() in filepath.lower() for pattern in SUSPICIOUS_PATTERNS):
        return True, "Pattern match"

    # Load Windows-specific vulnerabilities if running on Windows
    if current_os == 'windows':
        windows_patterns = load_windows_vulnerabilities()
        if any(pattern.lower() in filepath.lower() for pattern in windows_patterns):
            return True, "Windows vulnerability pattern match"

    # Load Linux malware hashes if running on Linux
    if current_os == 'linux':
        if linux_hashes is None:
            linux_hashes = load_linux_malware_hashes()
        file_hash = calculate_file_hash(filepath)
        if file_hash and file_hash in linux_hashes:
            return True, "Known Linux malware signature"

    # Check if hidden file (starts with . on Unix, or hidden attribute on Windows)
    if filepath.startswith('.') and platform.system() != 'Windows':
        return True, "Hidden file"

    return False, None

def scan_filesystem(start_path="/", current_os=None):
    suspect_files = []
    total_scanned = 0

    print("Scanning filesystem for malware...")
    print("Press Ctrl+C to stop scanning at any time.")

    try:
        if current_os is None:
            current_os = platform.system().lower()
            if current_os not in ['windows', 'darwin', 'linux']:
                current_os = 'linux'  # default

        for root, dirs, files in os.walk(start_path):
            try:
                for file in files:
                    filepath = os.path.join(root, file)
                    total_scanned += 1

                    # Skip very large files
                    try:
                        file_size = os.path.getsize(filepath)
                        if file_size > 100 * 1024 * 1024:  # Skip files > 100MB
                            continue
                    except OSError:
                        continue

                    # Skip certain directories
                    if any(skip in filepath for skip in ['/proc/', '/sys/', '/dev/', '/run/']):
                        continue

                    is_suspicious, reason = is_suspicious_file(filepath, current_os)
                    if is_suspicious:
                        suspect_files.append({
                            'filepath': filepath,
                            'reason': reason,
                            'size': file_size
                        })

                    # Show progress with current file name
                    if total_scanned % 50 == 0:
                        short_filename = os.path.basename(filepath)
                        if len(short_filename) > 30:
                            short_filename = short_filename[:27] + "..."
                        print(f"\rScanning: {short_filename} | {total_scanned} files, found {len(suspect_files)} suspicious...", end='', flush=True)

            except (PermissionError, OSError):
                continue

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")

    print(f"\nScan complete. Scanned {total_scanned} files, found {len(suspect_files)} suspicious files.\n")
    return suspect_files

def display_suspect_files(suspect_files):
    while suspect_files:
        print("Suspicious files found:")
        for i, file_info in enumerate(suspect_files, 1):
            filepath = file_info['filepath']
            reason = file_info['reason']
            size_mb = file_info.get('size', 0) / (1024 * 1024)
            print(f"{i:3d}. {filepath} ({reason}) - {size_mb:.2f} MB")

        print("\nOptions:")
        print("1. Delete selected files")
        print("2. Skip and continue")
        print("3. Show file details")

        choice = input("Enter your choice (1-3): ").strip()

        if choice == "1":
            delete_selected_files(suspect_files)
            break
        elif choice == "2":
            print("Skipping suspicious files...")
            suspect_files.clear()
            return
        elif choice == "3":
            show_file_details(suspect_files)
        else:
            print("Invalid choice.")

def delete_selected_files(suspect_files):
    if not suspect_files:
        return

    print("\nSelect files to delete (comma-separated numbers, or 'all' for all):")
    for i, file_info in enumerate(suspect_files, 1):
        filepath = file_info['filepath']
        print(f"{i:3d}. {filepath}")

    choice = input("Enter file numbers or 'all': ").strip().lower()

    to_delete = []
    if choice == 'all':
        to_delete = suspect_files
    else:
        indices = []
        try:
            indices = [int(x.strip()) - 1 for x in choice.split(',')]
            to_delete = [suspect_files[i] for i in indices if 0 <= i < len(suspect_files)]
        except ValueError:
            print("Invalid input.")
            return

    if not to_delete:
        print("No files selected for deletion.")
        return

    print("\nFiles to be deleted:")
    for file_info in to_delete:
        print(f"- {file_info['filepath']}")

    confirm = input("Are you sure you want to delete these files? (yes/no): ").strip().lower()
    if confirm == 'yes':
        for file_info in to_delete:
            try:
                os.remove(file_info['filepath'])
                print(f"Deleted: {file_info['filepath']}")
                suspect_files.remove(file_info)
            except OSError as e:
                print(f"Failed to delete {file_info['filepath']}: {e}")
    else:
        print("Deletion cancelled.")

def show_file_details(suspect_files):
    file_num = input("Enter file number to view details: ").strip()
    try:
        idx = int(file_num) - 1
        if 0 <= idx < len(suspect_files):
            file_info = suspect_files[idx]
            filepath = file_info['filepath']
            print(f"\n{'='*50}")
            print(f"File: {filepath}")
            print(f"Reason: {file_info['reason']}")
            try:
                size = os.path.getsize(filepath)
                print(f"Size: {size} bytes ({size/1024/1024:.2f} MB)")
                print(f"Last modified: {time.ctime(os.path.getmtime(filepath))}")
            except OSError:
                print("Could not retrieve file info.")
            print(f"{'='*50}\n")
        else:
            print("Invalid file number.")
    except ValueError:
        print("Invalid input.")

def main():
    clear_screen()

    # Display logo
    print(read_logo())

    # Loading phase
    loading_animation(3)

    # Main loop
    while True:
        choice = get_user_choice()

        if choice == "scan":
            try:
                suspect_files = scan_filesystem()
                if suspect_files:
                    display_suspect_files(suspect_files)
                else:
                    print("No suspicious files found.")
                input("\nPress Enter to return to main menu...")
            except Exception as e:
                print(f"Error during scan: {e}")
                input("\nPress Enter to return to main menu...")

        if choice == "stop":
            print("Exiting Paranoia Scanner...")
            sys.exit(0)

        # Refresh logo display after operations
        clear_screen()
        print(read_logo())
        print("\nParanoia Scanner ready.\n")

if __name__ == "__main__":
    main()
