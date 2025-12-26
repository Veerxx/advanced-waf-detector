from waf_detector import AdvancedWAFDetector

detector = AdvancedWAFDetector(
    target_url="https://example.com",
    verbose=True,
    aggressive=True
)

results = detector.run_detection()
print(results['final_detection'])
