#!/usr/bin/env python3
"""
Report Generator for WAF Detection Results
Generate HTML, PDF, and Markdown reports
"""

import json
import argparse
import webbrowser
from datetime import datetime
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Detection Report - {{ target }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #4CAF50;
        }
        .header h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .header .subtitle {
            color: #666;
            font-size: 1.1em;
        }
        .result-card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #4CAF50;
        }
        .result-card.detected {
            border-left-color: #4CAF50;
        }
        .result-card.not-detected {
            border-left-color: #f44336;
        }
        .waf-item {
            background: white;
            border-radius: 6px;
            padding: 15px;
            margin: 10px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .confidence-bar {
            height: 20px;
            background: #e0e0e0;
            border-radius: 10px;
            margin: 10px 0;
            overflow: hidden;
        }
        .confidence-fill {
            height: 100%;
            background: #4CAF50;
            border-radius: 10px;
            text-align: center;
            color: white;
            font-weight: bold;
            line-height: 20px;
            font-size: 12px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #4CAF50;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        .method-badge {
            display: inline-block;
            background: #2196F3;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            margin: 5px;
            font-size: 0.9em;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
            font-size: 0.9em;
        }
        .timestamp {
            color: #999;
            font-size: 0.8em;
        }
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 WAF Detection Report</h1>
            <div class="subtitle">
                Advanced WAF Detection Tool | Created by Veerxx
            </div>
            <div class="timestamp">
                Generated: {{ timestamp }}
            </div>
        </div>
        
        <div class="result-card {{ 'detected' if results.final_detection.waf_detected else 'not-detected' }}">
            <h2>
                {% if results.final_detection.waf_detected %}
                ✅ WAF Detected
                {% else %}
                ❌ No WAF Detected
                {% endif %}
            </h2>
            
            {% if results.final_detection.waf_detected %}
            <h3>Primary WAF: {{ results.final_detection.primary_waf }}</h3>
            
            <div class="confidence-bar">
                <div class="confidence-fill" style="width: {{ results.final_detection.confidence_score }}%">
                    {{ results.final_detection.confidence_score }}%
                </div>
            </div>
            
            <p>Confidence Level: <strong>{{ results.final_detection.confidence_level }}</strong></p>
            
            {% if results.final_detection.all_detected %}
            <h4>All Detected WAFs:</h4>
            {% for waf in results.final_detection.all_detected %}
            <div class="waf-item">
                <strong>{{ waf }}</strong>
                {% if waf in results.confidence_scores %}
                <div class="confidence-bar" style="margin: 5px 0;">
                    <div class="confidence-fill" style="width: {{ results.confidence_scores[waf] }}%; background: {% if results.confidence_scores[waf] > 70 %}#4CAF50{% elif results.confidence_scores[waf] > 40 %}#FF9800{% else %}#f44336{% endif %};">
                        {{ results.confidence_scores[waf] }}%
                    </div>
                </div>
                {% endif %}
            </div>
            {% endfor %}
            {% endif %}
            
            {% else %}
            <p>{{ results.final_detection.message }}</p>
            {% if results.final_detection.recommendation %}
            <p><strong>Recommendation:</strong> {{ results.final_detection.recommendation }}</p>
            {% endif %}
            {% endif %}
        </div>
        
        <h3>Detection Methods Used:</h3>
        <div>
            {% for method in results.detection_methods.keys() %}
            <span class="method-badge">{{ method }}</span>
            {% endfor %}
        </div>
        
        <h3>Statistics:</h3>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ results.statistics.requests_sent }}</div>
                <div class="stat-label">Requests Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ results.statistics.blocks_detected }}</div>
                <div class="stat-label">Blocks Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ results.statistics.timeouts }}</div>
                <div class="stat-label">Timeouts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ results.statistics.errors }}</div>
                <div class="stat-label">Errors</div>
            </div>
        </div>
        
        {% if results.behavior_analysis and results.behavior_analysis.block_rate_percent %}
        <div class="stat-card" style="max-width: 300px; margin: 20px auto;">
            <div class="stat-value">{{ results.behavior_analysis.block_rate_percent|round(1) }}%</div>
            <div class="stat-label">Overall Block Rate</div>
        </div>
        {% endif %}
        
        <div class="footer">
            <p>
                <strong>Tool:</strong> Advanced WAF Detector v{{ results.tool_info.version }}<br>
                <strong>Author:</strong> {{ results.tool_info.author }}<br>
                <strong>GitHub:</strong> <a href="{{ results.tool_info.github }}">{{ results.tool_info.github }}</a>
            </p>
            <p class="timestamp">
                Scan started: {{ results.timestamps.start }}<br>
                Scan ended: {{ results.timestamps.end }}
            </p>
        </div>
    </div>
</body>
</html>
"""

def generate_html_report(results, output_file):
    """Generate HTML report from results"""
    template = Template(HTML_TEMPLATE)
    
    html_content = template.render(
        target=results['target'],
        results=results,
        timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"[+] HTML report generated: {output_file}")
    return output_file

def generate_markdown_report(results, output_file):
    """Generate Markdown report from results"""
    md_content = f"""# WAF Detection Report

## Target
**URL:** {results['target']}
**Domain:** {results['domain']}

## Detection Results
{'**✅ WAF DETECTED**' if results['final_detection']['waf_detected'] else '**❌ NO WAF DETECTED**'}

"""
    
    if results['final_detection']['waf_detected']:
        md_content += f"""### Primary WAF
**{results['final_detection']['primary_waf']}**

### Confidence
**Score:** {results['final_detection']['confidence_score']}/100
**Level:** {results['final_detection']['confidence_level']}

### All Detected WAFs
"""
        for waf in results['final_detection'].get('all_detected', []):
            score = results['confidence_scores'].get(waf, 0)
            md_content += f"- {waf} ({score}/100)\n"
    else:
        md_content += f"\n{results['final_detection']['message']}\n"
    
    md_content += f"""
## Statistics
- **Requests Sent:** {results['statistics']['requests_sent']}
- **Blocks Detected:** {results['statistics']['blocks_detected']}
- **Timeouts:** {results['statistics']['timeouts']}
- **Errors:** {results['statistics']['errors']}
"""
    
    if 'behavior_analysis' in results and 'block_rate_percent' in results['behavior_analysis']:
        md_content += f"- **Block Rate:** {results['behavior_analysis']['block_rate_percent']:.1f}%\n"
    
    md_content += f"""
## Tool Information
- **Tool:** Advanced WAF Detector v{results['tool_info']['version']}
- **Author:** {results['tool_info']['author']}
- **GitHub:** {results['tool_info']['github']}
- **Scan Started:** {results['timestamps']['start']}
- **Scan Ended:** {results['timestamps']['end']}

---
*Report generated by Advanced WAF Detector*
"""
    
    with open(output_file, 'w') as f:
        f.write(md_content)
    
    print(f"[+] Markdown report generated: {output_file}")
    return output_file

def main():
    parser = argparse.ArgumentParser(description="Generate reports from WAF detection results")
    parser.add_argument("input_file", help="JSON results file")
    parser.add_argument("-f", "--format", choices=['html', 'md', 'pdf'], default='html',
                       help="Output format (default: html)")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("--open", action="store_true", help="Open HTML report in browser")
    
    args = parser.parse_args()
    
    # Load results
    with open(args.input_file, 'r') as f:
        results = json.load(f)
    
    # Determine output file name
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"waf_report_{timestamp}.{args.format}"
    
    # Generate report
    if args.format == 'html':
        output_file = generate_html_report(results, output_file)
        if args.open:
            webbrowser.open(f"file://{os.path.abspath(output_file)}")
    elif args.format == 'md':
        generate_markdown_report(results, output_file)
    elif args.format == 'pdf':
        print("[-] PDF generation requires additional dependencies")
        print("[+] Generating HTML instead...")
        output_file = generate_html_report(results, output_file.replace('.pdf', '.html'))
    
    print(f"[+] Report generation complete")

if __name__ == "__main__":
    main()
