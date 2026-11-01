import os
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template_string
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CloudScan/1.0'}
SQLI_PAYLOADS = ["'", "\"", "' OR 1=1 --", "\" OR 1=1 --"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]

# HTML for the phone interface. Clean, dark, mobile-first.
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Scanner</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #121212; color: #e0e0e0; padding: 20px; margin: 0; }
        h1 { color: #ff3b30; }
        input[type="text"] { width: 100%; padding: 12px; margin: 10px 0; background: #1e1e1e; border: 1px solid #333; color: white; border-radius: 8px; box-sizing: border-box; }
        button { width: 100%; padding: 15px; background: #ff3b30; color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 16px; }
        button:active { background: #cc2f26; }
        #results { margin-top: 20px; background: #1e1e1e; padding: 15px; border-radius: 8px; white-space: pre-wrap; font-family: monospace; font-size: 12px; min-height: 100px; }
        .vuln { color: #ff3b30; font-weight: bold; }
        .info { color: #30d158; }
    </style>
</head>
<body>
    <h1>Target Scanner</h1>
    <input type="text" id="targetUrl" placeholder="http://target.com" autocomplete="off">
    <button onclick="startScan()" id="scanBtn">Initiate Scan</button>
    <div id="results">Awaiting target...</div>

    <script>
        async function startScan() {
            const url = document.getElementById('targetUrl').value;
            const resultsDiv = document.getElementById('results');
            const btn = document.getElementById('scanBtn');
            
            if (!url) { alert("Enter a URL."); return; }
            
            btn.disabled = true;
            btn.innerText = "Scanning...";
            resultsDiv.innerHTML = "<span class='info'>[*] Initiating crawl and payload injection...</span>";

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                
                if (data.error) {
                    resultsDiv.innerHTML = `<span class="vuln">[!] Error: ${data.error}</span>`;
                } else {
                    let html = `<span class="info">[*] Scan complete. ${data.urls_scanned} URLs checked.</span>\\n\\n`;
                    if (data.findings.length === 0) {
                        html += "<span class='info'>[-] No obvious vulnerabilities found.</span>";
                    } else {
                        html += `<span class="vuln">[+] Vulnerabilities Found:</span>\\n`;
                        data.findings.forEach(f => { html += `<span class="vuln">${f}</span>\\n`; });
                    }
                    resultsDiv.innerHTML = html;
                }
            } catch (err) {
                resultsDiv.innerHTML = `<span class="vuln">[!] Network error.</span>`;
            }
            btn.disabled = false;
            btn.innerText = "Initiate Scan";
        }
    </script>
</body>
</html>
"""

class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(self.target_url).netloc
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.visited_urls = set()
        self.vulnerabilities = []

    def crawl(self, url):
        if url in self.visited_urls or len(self.visited_urls) > 30:
            return []
        self.visited_urls.add(url)
        try:
            response = self.session.get(url, timeout=5, verify=False)
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return []
            soup = BeautifulSoup(response.text, 'html.parser')
            links = set()
            for a_tag in soup.find_all('a', href=True):
                full_url = urljoin(url, a_tag['href'])
                if urlparse(full_url).netloc == self.domain:
                    links.add(full_url)
            return list(links)
        except requests.RequestException:
            return []

    def scan_forms(self, url):
        try:
            response = self.session.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(url, action)
                inputs = form.find_all(['input', 'textarea'])
                
                for sqli in SQLI_PAYLOADS:
                    payload_map = {inp.get('name'): sqli for inp in inputs if inp.get('name') and inp.get('type') != 'submit'}
                    self._test_payload(form_url, method, payload_map, "SQL Injection", sqli)
                
                for xss in XSS_PAYLOADS:
                    payload_map = {inp.get('name'): xss for inp in inputs if inp.get('name') and inp.get('type') != 'submit'}
                    self._test_payload(form_url, method, payload_map, "Reflected XSS", xss)
        except requests.RequestException:
            pass

    def _test_payload(self, url, method, payload_map, vuln_type, payload):
        if not payload_map: return
        try:
            if method == 'post':
                res = self.session.post(url, data=payload_map, timeout=5, verify=False)
            else:
                res = self.session.get(url, params=payload_map, timeout=5, verify=False)
            
            if "SQL Injection" in vuln_type and any(err in res.text for err in ["SQL syntax", "mysql_fetch", "ORA-"]):
                self._report_vuln(url, vuln_type, payload)
            elif "XSS" in vuln_type and payload in res.text:
                self._report_vuln(url, vuln_type, payload)
        except requests.RequestException:
            pass

    def _report_vuln(self, url, vuln_type, payload):
        finding = f"[!] {vuln_type} at {url} | Payload: {payload}"
        if finding not in self.vulnerabilities:
            self.vulnerabilities.append(finding)

    def run(self):
        to_crawl = [self.target_url]
        with ThreadPoolExecutor(max_workers=5) as executor:
            while to_crawl:
                futures = {executor.submit(self.crawl, url): url for url in to_crawl}
                to_crawl = []
                for future in as_completed(futures):
                    to_crawl.extend(future.result())

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.scan_forms, url) for url in self.visited_urls]
            for future in as_completed(futures): future.result()
        
        return len(self.visited_urls), self.vulnerabilities

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    target = data.get('url')
    if not target:
        return jsonify({"error": "No URL provided"}), 400
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    scanner = WebScanner(target)
    urls_scanned, findings = scanner.run()
    return jsonify({"urls_scanned": urls_scanned, "findings": findings})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
