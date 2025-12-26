from waf_detector import AdvancedWAFDetector

# Initialize detector
detector = AdvancedWAFDetector(
    target_url="https://example.com",
    verbose=True,
    aggressive=False,
    threads=5
)

# Run detection
results = detector.run_detection()

# Access results
if results['final_detection']['waf_detected']:
    print(f"WAF Detected: {results['final_detection']['primary_waf']}")
    print(f"Confidence: {results['final_detection']['confidence_score']}%")
