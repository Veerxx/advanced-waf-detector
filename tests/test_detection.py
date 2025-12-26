import json
from waf_detector import AdvancedWAFDetector

def batch_scan(targets_file):
    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    results = []
    for target in targets:
        print(f"Scanning: {target}")
        detector = AdvancedWAFDetector(target)
        result = detector.run_detection()
        results.append(result)
        
        # Save individual result
        filename = f"scan_{target.replace('://', '_').replace('/', '_')}.json"
        with open(filename, 'w') as f:
            json.dump(result, f, indent=2)
    
    return results

# Run batch scan
batch_scan("targets.txt")
