python waf_detector.py https://example.com

Verbose Mode

python waf_detector.py example.com -v


python waf_detector.py target.com -o scan_results.json

python waf_detector.py target.com -a

python waf_detector.py target.com -s


python waf_detector.py target.com --proxy http://localhost:8080
python waf_detector.py target.com --proxy socks5://127.0.0.1:9050

python waf_detector.py target.com -t 20 -T 30
