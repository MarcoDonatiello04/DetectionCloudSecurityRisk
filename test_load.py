from cloud_security_analyzer.services.scan_service import ScanService
scan = ScanService("/Users/marcodonatiello/Desktop/DetectionCloudSecurityRisk/reports")
findings = scan.load_findings()
checkovs = [f for f in findings if f.source == "CHECKOV"]
print(f"Total findings: {len(findings)}")
print(f"Checkov findings: {len(checkovs)}")
if len(checkovs) > 0:
    print(checkovs[0].source, type(checkovs[0].source))
