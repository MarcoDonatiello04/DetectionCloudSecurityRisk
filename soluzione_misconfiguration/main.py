import sys
import os
import json

# Add root folder of project to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from soluzione_misconfiguration.checkov_scanner import CheckovScanner

def main():
    target_dir = "problema_misconfiguration"
    if len(sys.argv) > 1:
        target_dir = sys.argv[1]
        
    print(f"🔍 Starting Checkov Scan on directory: {target_dir}")
    scanner = CheckovScanner()
    findings = scanner.scan(target_dir)
    
    print(f"\n📊 --- Checkov Scan Summary ---")
    print(f"Found {len(findings)} issues.")
    
    # Group findings by category and severity
    for f in findings:
        print(f"  - [{f.severity.value}] {f.title} | Resource: {f.resource_id} | Location: {f.location.file_path}:{f.location.start_line}")
        
    print("---------------------------------\n")

if __name__ == "__main__":
    main()
