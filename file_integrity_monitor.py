#!/usr/bin/env python3
"""
File Integrity Monitor
Detects unauthorized file modifications, deletions, and creations
"""

import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path

class FileIntegrityMonitor:
    def __init__(self, baseline_file='file_baseline.json'):
        self.baseline_file = baseline_file
        self.baseline = {}
        self.changes = {
            'modified': [],
            'deleted': [],
            'created': []
        }
    
    def calculate_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            return None
    
    def create_baseline(self, directory):
        """Create baseline of files in directory"""
        print(f"\n{'='*70}")
        print("CREATING FILE INTEGRITY BASELINE")
        print(f"{'='*70}")
        print(f"Directory: {directory}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        file_count = 0
        for root, dirs, files in os.walk(directory):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if file.startswith('.'):
                    continue
                
                filepath = os.path.join(root, file)
                try:
                    file_hash = self.calculate_hash(filepath)
                    if file_hash:
                        file_stat = os.stat(filepath)
                        self.baseline[filepath] = {
                            'hash': file_hash,
                            'size': file_stat.st_size,
                            'modified': file_stat.st_mtime,
                            'created': datetime.now().isoformat()
                        }
                        file_count += 1
                        if file_count % 10 == 0:
                            print(f"Processed {file_count} files...", end='\r')
                except Exception as e:
                    print(f"Error processing {filepath}: {e}")
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline, f, indent=2)
        
        print(f"\n\n✓ Baseline created: {file_count} files")
        print(f"✓ Saved to: {self.baseline_file}")
        print(f"{'='*70}\n")
    
    def load_baseline(self):
        """Load existing baseline"""
        try:
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
            return True
        except FileNotFoundError:
            print(f"Error: Baseline file '{self.baseline_file}' not found")
            print("Run 'Create Baseline' first!")
            return False
        except Exception as e:
            print(f"Error loading baseline: {e}")
            return False
    
    def scan_changes(self, directory):
        """Scan for changes since baseline"""
        if not self.load_baseline():
            return
        
        print(f"\n{'='*70}")
        print("SCANNING FOR FILE CHANGES")
        print(f"{'='*70}")
        print(f"Directory: {directory}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        current_files = set()
        baseline_files = set(self.baseline.keys())
        
        # Check existing files
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if file.startswith('.'):
                    continue
                
                filepath = os.path.join(root, file)
                current_files.add(filepath)
                
                current_hash = self.calculate_hash(filepath)
                if not current_hash:
                    continue
                
                if filepath in self.baseline:
                    # File existed in baseline - check if modified
                    if current_hash != self.baseline[filepath]['hash']:
                        file_stat = os.stat(filepath)
                        self.changes['modified'].append({
                            'file': filepath,
                            'old_hash': self.baseline[filepath]['hash'],
                            'new_hash': current_hash,
                            'old_size': self.baseline[filepath]['size'],
                            'new_size': file_stat.st_size,
                            'detected': datetime.now().isoformat()
                        })
                else:
                    # New file created
                    file_stat = os.stat(filepath)
                    self.changes['created'].append({
                        'file': filepath,
                        'hash': current_hash,
                        'size': file_stat.st_size,
                        'detected': datetime.now().isoformat()
                    })
        
        # Check for deleted files
        deleted_files = baseline_files - current_files
        for filepath in deleted_files:
            self.changes['deleted'].append({
                'file': filepath,
                'hash': self.baseline[filepath]['hash'],
                'detected': datetime.now().isoformat()
            })
        
        self._generate_report()
    
    def _generate_report(self):
        """Generate change detection report"""
        print(f"\n{'='*70}")
        print("FILE INTEGRITY REPORT")
        print(f"{'='*70}")
        print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        total_changes = (len(self.changes['modified']) + 
                        len(self.changes['deleted']) + 
                        len(self.changes['created']))
        
        print(f"{'─'*70}")
        print("SUMMARY")
        print(f"{'─'*70}")
        print(f"Files Modified: {len(self.changes['modified'])}")
        print(f"Files Deleted:  {len(self.changes['deleted'])}")
        print(f"Files Created:  {len(self.changes['created'])}")
        print(f"Total Changes:  {total_changes}")
        print()
        
        if total_changes == 0:
            print("✓ No changes detected - File integrity maintained")
            print(f"{'='*70}\n")
            return
        
        # Modified files
        if self.changes['modified']:
            print(f"{'─'*70}")
            print("⚠️  MODIFIED FILES")
            print(f"{'─'*70}")
            for change in self.changes['modified']:
                print(f"File: {change['file']}")
                print(f"  Size: {change['old_size']} → {change['new_size']} bytes")
                print(f"  Hash: {change['old_hash'][:16]}... → {change['new_hash'][:16]}...")
                print()
        
        # Deleted files
        if self.changes['deleted']:
            print(f"{'─'*70}")
            print("🗑️  DELETED FILES")
            print(f"{'─'*70}")
            for change in self.changes['deleted']:
                print(f"File: {change['file']}")
                print(f"  Hash: {change['hash'][:16]}...")
                print()
        
        # Created files
        if self.changes['created']:
            print(f"{'─'*70}")
            print("📄 NEW FILES")
            print(f"{'─'*70}")
            for change in self.changes['created']:
                print(f"File: {change['file']}")
                print(f"  Size: {change['size']} bytes")
                print(f"  Hash: {change['hash'][:16]}...")
                print()
        
        # Security recommendations
        print(f"{'─'*70}")
        print("SECURITY RECOMMENDATIONS")
        print(f"{'─'*70}")
        
        if self.changes['modified']:
            print("⚠️  Investigate all modified files")
            print("   → Verify changes are authorized")
            print("   → Check for signs of malware/ransomware")
        
        if self.changes['deleted']:
            print("⚠️  Critical: Files have been deleted")
            print("   → Determine if deletion was authorized")
            print("   → Check backup systems")
        
        if len(self.changes['created']) > 10:
            print("⚠️  High number of new files created")
            print("   → May indicate malware installation")
            print("   → Scan with antivirus")
        
        print()
        print(f"{'='*70}\n")
        
        # Save report
        report_file = f"integrity_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(self.changes, f, indent=2)
        print(f"✓ Report saved to: {report_file}")

def main():
    monitor = FileIntegrityMonitor()
    
    print("="*70)
    print("FILE INTEGRITY MONITOR")
    print("="*70)
    print("\nDetects unauthorized file modifications, deletions, and creations")
    print()
    
    print("Options:")
    print("1. Create baseline (first time setup)")
    print("2. Scan for changes")
    print("3. Exit")
    
    choice = input("\nSelect option (1-3): ")
    
    if choice == '1':
        directory = input("\nEnter directory to monitor (default: current dir): ") or "."
        directory = os.path.abspath(directory)
        
        if not os.path.exists(directory):
            print(f"Error: Directory '{directory}' not found")
            return
        
        monitor.create_baseline(directory)
    
    elif choice == '2':
        directory = input("\nEnter directory to scan (default: current dir): ") or "."
        directory = os.path.abspath(directory)
        
        if not os.path.exists(directory):
            print(f"Error: Directory '{directory}' not found")
            return
        
        monitor.scan_changes(directory)
    
    elif choice == '3':
        print("\nExiting...")
    
    else:
        print("\nInvalid option")

if __name__ == "__main__":
    main()
