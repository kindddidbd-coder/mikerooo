import os
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template_string
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hidden Wiki Scraper</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #121212; color: #e0e0e0; padding: 20px; margin: 0; }
        h1 { color: #ff3b30; }
        .input-group { display: flex; gap: 10px; margin-bottom: 20px; }
        input[type="text"] { flex: 1; padding: 12px; background: #1e1e1e; border: 1px solid #333; color: white; border-radius: 8px; }
        button { padding: 12px 20px; background: #ff3b30; color: white; border: none; border-radius: 8px; font-weight: bold; font-size: 16px; cursor: pointer; }
        button:active { background: #cc2f26; }
        button:disabled { background: #555; cursor: not-allowed; }
        #results { margin-top: 20px; background: #1e1e1e; padding: 15px; border-radius: 8px; white-space: pre-wrap; font-family: monospace; font-size: 12px; max-height: 600px; overflow-y: auto; }
        .found { color: #30d158; font-weight: bold; margin-bottom: 8px; word-break: break-all; }
        .error { color: #ff3b30; }
    </style>
</head>
<body>
    <h1>Hidden Wiki Extractor</h1>
    <div class="input-group">
        <input type="text" id="targetUrl" placeholder="https://thehiddenwiki.org/" autocomplete="off">
        <button onclick="startScrape()" id="scrapeBtn">Extract Links</button>
    </div>
    <div id="results">Awaiting target...</div>

    <script>
        async function startScrape() {
            const url = document.getElementById('targetUrl').value;
            const resultsDiv = document.getElementById('results');
            const btn = document.getElementById('scrapeBtn');
            
            if (!url) { alert("Enter a URL."); return; }
            
            btn.disabled = true;
            btn.innerText = "Scraping...";
            resultsDiv.innerHTML = "<span style='color: #ffcc00;'>[*] Fetching page and finding .onion links...</span>";

            try {
                const response = await fetch('/scrape', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const data = await response.json();
                
                if (data.error) {
                    resultsDiv.innerHTML = `<span class="error">[!] Error: ${data.error}</span>`;
                } else {
                    if (data.links.length === 0) {
                        resultsDiv.innerHTML = "<span class='error'>[-] No .onion links found.</span>";
                    } else {
                        let html = `<span style='color:#30d158'>[+] Found ${data.links.length} .onion links:</span>\\n\\n`;
                        data.links.forEach(link => {
                            html += `<div class="found">${link}</div>`;
                        });
                        resultsDiv.innerHTML = html;
                    }
                }
            } catch (err) {
                resultsDiv.innerHTML = `<span class="error">[!] Network error.</span>`;
            }
            btn.disabled = false;
            btn.innerText = "Extract Links";
        }
    </script>
</body>
</html>
"""

def extract_onion_links(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    try:
        res = requests.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(res.text, 'html.parser')
        
        onion_links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if '.onion' in href:
                onion_links.add(href)
                
        return list(onion_links)
    except Exception as e:
        return {"error": str(e)}

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scrape', methods=['POST'])
def api_scrape():
    data = request.get_json()
    target = data.get('url')
    
    if not target:
        return jsonify({"error": "No URL provided"}), 400
        
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    result = extract_onion_links(target)
    
    if isinstance(result, dict) and "error" in result:
        return jsonify(result)
        
    return jsonify({"links": result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))