import os
import argparse
import logging
import json
from pathlib import Path
from proxy_manager import ProxyManager
from dynamic_analysis import DynamicAnalyzer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def analyze_traffic_file(mitm_file):
    """
    Very basic traffic analysis. In a real scenario, you'd use mitmproxy's io library
    to parse the requests and check domains.
    """
    suspicious_domains = ['casino', 'bet', 'gamble', 'poker', 'slots']
    found = []
    
    if not os.path.exists(mitm_file):
        return found
        
    try:
        # Just grep the file for basic strings as a naive approach.
        # Alternatively, use mitmproxy.io.FlowReader
        from mitmproxy import io
        from mitmproxy.exceptions import FlowReadException
        with open(mitm_file, "rb") as logfile:
            freader = io.FlowReader(logfile)
            try:
                for flow in freader.stream():
                    if hasattr(flow, 'request'):
                        url = flow.request.pretty_url
                        for kw in suspicious_domains:
                            if kw in url.lower() and url not in found:
                                found.append(url)
            except FlowReadException as e:
                logging.error(f"Error reading mitm file: {e}")
    except ImportError:
        logging.warning("mitmproxy library not available for parsing.")
        
    return found

def main(apk_path, max_proxies=2, output_dir="artifacts"):
    apk_path = Path(apk_path)
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    logging.info(f"Starting AAMT Analysis on {apk_path}")
    
    # 1. Get Proxies
    pm = ProxyManager()
    proxies = pm.get_working_proxies(limit=max_proxies)
    
    if not proxies:
        logging.warning("No working proxies found. Will run without proxy.")
        proxies = [None]
        
    # 3. Dynamic Analysis per Proxy
    da = DynamicAnalyzer(output_dir=output_dir)
    dynamic_results = {}
    
    for proxy in proxies:
        if proxy:
            logging.info(f"Running dynamic analysis through proxy: {proxy}")
            result_key = proxy
        else:
            logging.info("Running dynamic analysis locally without an upstream proxy")
            result_key = "noproxy"

        report_file = da.run_analysis(apk_path, proxy)
        suspicious = analyze_traffic_file(report_file)
        dynamic_results[result_key] = {
            "traffic_file": report_file,
            "suspicious_urls": suspicious,
        }
            
    # 3. Generate Final Report
    report = {
        'apk': str(apk_path),
        'dynamic_analysis': dynamic_results
    }
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    report_path = Path(output_dir) / "aamt_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)
        
    logging.info(f"Analysis complete. Report saved to {report_path}")
    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Android Automated Malware Analysis Tool")
    parser.add_argument("apk_path", help="Path to the APK file")
    parser.add_argument("--proxies", type=int, default=2, help="Number of proxies to test against")
    parser.add_argument("--output-dir", default="artifacts", help="Directory for reports, traffic dumps, and screenshots")
    args = parser.parse_args()
    
    main(args.apk_path, args.proxies, args.output_dir)
