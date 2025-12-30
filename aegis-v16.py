import threading
import time
import uuid
import queue
import socket
import json
import random
import re
import urllib3
import os
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, Response, request, render_template_string, jsonify, stream_with_context
import requests
import dns.resolver

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ================= CONFIGURATION =================
DEFAULT_WORDLIST = [
    'www', 'mail', 'ftp', 'admin', 'login', 'dashboard', 'dev', 'test', 
    'api', 'shop', 'blog', 'staging', 'support', 'help', 'images', 
    'uploads', 'secure', 'vpn', 'remote', 'portal', 'webmail', 'config',
    'auth', 'status', 'docs', 'backup', 'billing', 'cpanel', 'mobile',
    'sitemap.xml', 'robots.txt', '.env', '.git/HEAD', 'wp-admin', 'shell',
    'jenkins', 'jira', 'gitlab', 'sql', 'db', 'mysql', 'oracle', 'user',
    'assets', 'static', 'media', 'files', 'archive', 'private', 'debug',
    'id_rsa', 'backup.sql', 'database.yml', 'settings.py'
]

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "AegisV16/16.0 (Security Scan)"
]

scans = {}

class Scanner:
    def __init__(self, scan_id, target, wordlist, threads=50, modules=None):
        self.id = scan_id
        if target.startswith("http"):
            self.clean_target = target.replace("http://", "").replace("https://", "").rstrip('/').split('/')[0]
            self.base_protocol = target.split("://")[0]
        else:
            self.clean_target = target.rstrip('/').split('/')[0]
            self.base_protocol = "auto"

        self.target_ip = "Resolving..."
        self.wordlist = wordlist
        self.threads = int(threads)
        self.modules = modules if modules else {'sub': True, 'dir': True, 'port': 'fast'}
        
        self.stop_event = threading.Event()
        self.msg_queue = queue.Queue()
        
        self.ports_to_scan = []
        if self.modules.get('port') == "fast": self.ports_to_scan = TOP_PORTS
        elif self.modules.get('port') == "full": self.ports_to_scan = list(range(1, 65536))
        
        count_sub = len(self.wordlist) if self.modules.get('sub') else 0
        count_dir = len(self.wordlist) if self.modules.get('dir') else 0
        count_port = len(self.ports_to_scan) if self.modules.get('port') != 'none' else 0
        
        self.total_tasks = count_sub + count_dir + count_port
        self.completed_tasks = 0
        self.lock = threading.Lock()
        
        self.start_time = time.time()
        self.requests_made = 0

    def emit(self, type, data):
        self.msg_queue.put(json.dumps({"type": type, "data": data}))

    def update_stats(self):
        with self.lock:
            self.completed_tasks += 1
            self.requests_made += 1
            pct = int((self.completed_tasks / self.total_tasks) * 100) if self.total_tasks > 0 else 0
            elapsed = time.time() - self.start_time
            rps = int(self.requests_made / elapsed) if elapsed > 0 else 0
            
        if self.completed_tasks % 5 == 0 or pct >= 100:
            self.emit("stats", {"progress": pct, "rps": rps, "tasks": self.completed_tasks, "total": self.total_tasks})

    def probe_url(self, url):
        start = time.time()
        try:
            with requests.Session() as s:
                s.verify = False
                s.headers.update({'User-Agent': random.choice(USER_AGENTS)})
                r = s.get(url, timeout=4, allow_redirects=True)
                
                latency = int((time.time() - start) * 1000)
                code = str(r.status_code)
                size = len(r.content)
                title = "No Title"
                try:
                    m = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
                    if m: title = m.group(1)[:25].strip()
                except: pass

                if r.history:
                    chain = " -> ".join([str(h.status_code) for h in r.history]) + f" -> {code}"
                    meta = f"{chain} | {title}"
                else:
                    meta = f"{size}b | {title}"
                return code, meta, latency, url

        except requests.exceptions.ConnectTimeout: return "TIMEOUT_C", "Connect Timed Out", 0, url
        except requests.exceptions.ReadTimeout: return "TIMEOUT_R", "Read Timed Out", 0, url
        except requests.exceptions.SSLError: return "SSL_FAIL", "SSL Handshake Failed", 0, url
        except requests.exceptions.ConnectionError: return "REFUSED", "Connection Refused", 0, url
        except: return "ERR", "Unknown Error", 0, url

    def smart_probe(self, domain):
        code, meta, lat, link = self.probe_url(f"https://{domain}")
        if code not in ["TIMEOUT_C", "REFUSED", "ERR"]:
            return code, meta, lat, link
        return self.probe_url(f"http://{domain}")

    def scan_port(self, port):
        if self.stop_event.is_set(): return
        status = "CLOSED"
        meta = "-"
        latency = 0
        t_start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7)
            if sock.connect_ex((self.clean_target, port)) == 0:
                latency = int((time.time() - t_start) * 1000)
                status = "OPEN"
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').split('\n')[0].strip()
                    meta = banner[:30] if banner else "TCP Service"
                except: meta = "TCP Service"
            sock.close()
        except: status = "ERR"
        
        self.emit("result", {
            "cat": "port", "val": f"Port {port}", "code": status,
            "ip": self.target_ip, "meta": meta, "lat": f"{latency}ms", "link": "#"
        })
        self.update_stats()

    def scan_subdomain(self, word):
        if self.stop_event.is_set(): return
        full = f"{word}.{self.clean_target}"
        code = "NXDOMAIN"
        ip = "-"
        meta = "DNS Resolution Failed"
        link = "#"
        latency = 0

        try:
            res = dns.resolver.Resolver()
            res.nameservers = ['8.8.8.8']
            ans = res.resolve(full, 'A')
            ip = ans[0].address
            code, meta, latency, link = self.smart_probe(full)
        except dns.resolver.NXDOMAIN: code = "NXDOMAIN"
        except: code = "DNS_ERR"

        self.emit("result", {
            "cat": "sub", "val": full, "code": code,
            "ip": ip, "meta": meta, "lat": f"{latency}ms", "link": link
        })
        self.update_stats()

    def scan_directory(self, word):
        if self.stop_event.is_set(): return
        proto = self.base_protocol if self.base_protocol != "auto" else "http"
        url = f"{proto}://{self.clean_target}/{word}"
        code, meta, lat, link = self.probe_url(url)
        
        self.emit("result", {
            "cat": "dir", "val": f"/{word}", "code": code,
            "ip": self.target_ip, "meta": meta, "lat": f"{lat}ms", "link": link
        })
        self.update_stats()

    def start(self):
        try:
            self.target_ip = socket.gethostbyname(self.clean_target)
        except: self.target_ip = "Unknown"
        self.emit("info", {"ip": self.target_ip})
        
        workers = self.threads
        if len(self.wordlist) > 2000 and workers < 150: workers = 150

        with ThreadPoolExecutor(max_workers=workers) as executor:
            if self.modules.get('port') != 'none':
                for p in self.ports_to_scan: executor.submit(self.scan_port, p)
            if self.modules.get('sub'):
                for w in self.wordlist: executor.submit(self.scan_subdomain, w)
            if self.modules.get('dir'):
                for w in self.wordlist: executor.submit(self.scan_directory, w)
            
        self.emit("done", None)
        self.msg_queue.put(None)

# ================= UI =================
HTML_UI = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Aegis V16 Zenith</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root { 
            --bg-dark: #050505;
            --bg-panel: #0a0a0a;
            --border: #222;
            --accent: #00e5ff;
            --success: #00ff9d;
            --warning: #ffb700;
            --danger: #ff3333;
            --text-main: #ffffff;
            --text-muted: #888888;
            --font-main: 'Inter', sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }
        
        * { box-sizing: border-box; scrollbar-width: thin; scrollbar-color: var(--border) var(--bg-panel); }
        body { background: var(--bg-dark); color: var(--text-main); font-family: var(--font-main); margin: 0; height: 100vh; display: grid; grid-template-rows: 60px 1fr; overflow: hidden; }
        
        /* SCROLLBAR */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-dark); }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #444; }

        /* HEADER */
        .header { 
            background: rgba(10, 10, 10, 0.95); 
            border-bottom: 1px solid var(--border); 
            display: flex; align-items: center; justify-content: space-between; 
            padding: 0 30px; 
            z-index: 100;
            backdrop-filter: blur(10px);
        }
        
        .brand { font-family: var(--font-mono); font-weight: 800; font-size: 1.4rem; color: var(--text-main); letter-spacing: -1px; }
        .brand span { color: var(--accent); }
        
        .intel-wrap { display: flex; gap: 30px; font-size: 0.85rem; font-family: var(--font-mono); color: var(--text-muted); }
        .intel-item span { color: var(--success); font-weight: bold; }
        
        .progress-bar { position: absolute; bottom: 0; left: 0; height: 2px; background: var(--accent); width: 0%; transition: width 0.4s ease; box-shadow: 0 0 15px var(--accent); }

        /* MAIN LAYOUT */
        .main-container { display: grid; grid-template-columns: 340px 1fr; height: 100%; overflow: hidden; }

        /* SIDEBAR */
        .sidebar { background: var(--bg-panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; padding: 25px; gap: 25px; overflow-y: auto; }
        
        .section-header { font-size: 0.7rem; font-weight: 800; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 12px; display: block; }
        
        .input-group { margin-bottom: 15px; position: relative; }
        .input-label { display: block; font-size: 0.75rem; color: var(--text-muted); font-weight: 600; margin-bottom: 8px; }
        
        input[type="text"], input[type="number"], select { 
            width: 100%; background: #111; border: 1px solid var(--border); 
            color: var(--text-main); padding: 12px; border-radius: 6px; 
            font-family: var(--font-mono); font-size: 0.85rem; transition: 0.2s; 
        }
        input:focus, select:focus { border-color: var(--accent); outline: none; box-shadow: 0 0 0 2px rgba(0, 229, 255, 0.1); }

        /* MODULE TOGGLES */
        .toggle-card { background: #111; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .toggle-row { display: flex; justify-content: space-between; align-items: center; padding: 12px 15px; cursor: pointer; border-bottom: 1px solid var(--border); transition: 0.2s; }
        .toggle-row:last-child { border-bottom: none; }
        .toggle-row:hover { background: #1a1a1a; }
        .toggle-row.active { background: rgba(0, 229, 255, 0.05); }
        .toggle-row.active span { color: var(--accent); font-weight: 600; }
        
        .checkbox-circle { width: 16px; height: 16px; border: 2px solid var(--text-muted); border-radius: 50%; position: relative; transition: 0.2s; }
        .toggle-row.active .checkbox-circle { border-color: var(--accent); background: var(--accent); box-shadow: 0 0 10px rgba(0, 229, 255, 0.4); }

        /* FILE UPLOAD */
        .upload-box { 
            border: 2px dashed var(--border); border-radius: 8px; padding: 20px; 
            text-align: center; cursor: pointer; transition: 0.3s; position: relative; 
            background: linear-gradient(145deg, #111, #0d0d0d);
        }
        .upload-box:hover { border-color: var(--accent); background: rgba(0, 229, 255, 0.02); }
        .upload-box.active { border-color: var(--success); border-style: solid; }
        .upload-label { font-size: 0.75rem; color: var(--text-muted); font-weight: 500; }
        .file-reset { position: absolute; top: 8px; right: 10px; color: var(--danger); cursor: pointer; display: none; font-weight: bold; }

        /* BUTTONS */
        .btn-group { display: flex; flex-direction: column; gap: 10px; margin-top: auto; }
        .btn { padding: 14px; border: none; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; transition: 0.2s; }
        .btn-start { background: var(--accent); color: #000; box-shadow: 0 4px 15px rgba(0, 229, 255, 0.2); }
        .btn-start:hover { background: #33eeff; transform: translateY(-2px); }
        .btn-stop { background: transparent; border: 1px solid var(--danger); color: var(--danger); }
        .btn-stop:hover { background: var(--danger); color: #fff; }

        /* CONTENT AREA */
        .content { display: flex; flex-direction: column; overflow: hidden; position: relative; }
        
        .tabs-container { display: flex; background: var(--bg-panel); border-bottom: 1px solid var(--border); padding: 0 25px; gap: 25px; }
        .tab { padding: 18px 0; cursor: pointer; font-size: 0.8rem; font-weight: 600; color: var(--text-muted); border-bottom: 2px solid transparent; transition: 0.2s; }
        .tab:hover { color: var(--text-main); }
        .tab.active { color: var(--accent); border-bottom-color: var(--accent); }

        /* FILTER BAR */
        .filter-bar { padding: 15px 25px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; overflow-x: auto; background: rgba(5, 5, 5, 0.8); backdrop-filter: blur(5px); min-height: 65px; }
        .filter-title { font-size: 0.7rem; font-weight: 800; color: var(--text-muted); margin-right: 10px; }
        
        .chip { 
            display: flex; align-items: center; padding: 6px 12px; background: #151515; 
            border-radius: 20px; font-size: 0.75rem; cursor: pointer; border: 1px solid var(--border); 
            color: var(--text-muted); transition: 0.2s; font-family: var(--font-mono); user-select: none; 
        }
        .chip:hover { border-color: var(--text-muted); color: var(--text-main); }
        .chip.active { background: rgba(0, 229, 255, 0.15); border-color: var(--accent); color: var(--accent); font-weight: bold; }
        .chip-badge { margin-left: 8px; font-size: 0.65rem; background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 10px; }

        /* DATA GRID */
        .grid-container { flex: 1; overflow-y: auto; display: flex; flex-direction: column; }
        .grid-head { 
            display: grid; grid-template-columns: 80px 2fr 100px 140px 100px 250px; 
            padding: 12px 25px; background: #111; border-bottom: 1px solid var(--border); 
            font-size: 0.7rem; color: var(--text-muted); font-weight: 700; 
            position: sticky; top: 0; z-index: 10;
        }
        
        .row { 
            display: grid; grid-template-columns: 80px 2fr 100px 140px 100px 250px; 
            padding: 10px 25px; border-bottom: 1px solid #1a1a1a; font-size: 0.85rem; 
            align-items: center; transition: 0.1s; font-family: var(--font-main); 
        }
        .row:hover { background: #131313; }
        
        .cell-cat { font-size: 0.65rem; font-weight: 800; color: var(--text-muted); text-transform: uppercase; background: #1a1a1a; padding: 3px 8px; border-radius: 4px; width: fit-content; }
        .cell-val { font-family: var(--font-mono); color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 0.85rem; }
        .cell-val a { color: inherit; text-decoration: none; border-bottom: 1px dotted #444; transition: 0.2s; }
        .cell-val a:hover { color: var(--accent); border-color: var(--accent); }
        
        .status-pill { padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 0.7rem; font-family: var(--font-mono); text-align: center; display: inline-block; min-width: 60px; }
        
        /* STATUS COLORS */
        .st-ok { background: rgba(0, 255, 157, 0.1); color: var(--success); border: 1px solid rgba(0, 255, 157, 0.2); }
        .st-warn { background: rgba(255, 183, 0, 0.1); color: var(--warning); border: 1px solid rgba(255, 183, 0, 0.2); }
        .st-err { background: rgba(255, 51, 51, 0.1); color: var(--danger); border: 1px solid rgba(255, 51, 51, 0.2); }
        .st-info { background: rgba(0, 229, 255, 0.1); color: var(--accent); border: 1px solid rgba(0, 229, 255, 0.2); }
        .st-dim { background: #1a1a1a; color: var(--text-muted); border: 1px solid #333; }

        .cell-ip { color: var(--text-muted); font-size: 0.75rem; font-family: var(--font-mono); }
        .cell-meta { color: var(--text-muted); font-size: 0.75rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-style: italic; }

    </style>
</head>
<body>
    <div class="header">
        <div class="brand">AEGIS <span>V16</span></div>
        <div class="intel-wrap">
            <div class="intel-item">TARGET: <span id="tIp" style="color:var(--text-main)">Waiting...</span></div>
            <div class="intel-item">RATE: <span id="tRps">0</span> RPS</div>
            <div class="intel-item">TASKS: <span id="tProg">0 / 0</span></div>
        </div>
        <div class="progress-bar" id="pBar"></div>
    </div>

    <div class="main-container">
        <div class="sidebar">
            <div>
                <span class="section-header">Target Scope</span>
                <div class="input-group">
                    <label class="input-label">DOMAIN / URL</label>
                    <input type="text" id="tInput" placeholder="example.com">
                </div>
            </div>

            <div>
                <span class="section-header">Modules</span>
                <div class="toggle-card">
                    <div class="toggle-row active" id="mSub" onclick="toggle('sub')">
                        <span>Subdomain Enumeration</span><div class="checkbox-circle"></div>
                    </div>
                    <div class="toggle-row active" id="mDir" onclick="toggle('dir')">
                        <span>Directory Brute Force</span><div class="checkbox-circle"></div>
                    </div>
                </div>
                <div class="input-group" style="margin-top:15px;">
                    <label class="input-label">PORT SCANNING</label>
                    <select id="mPort">
                        <option value="none">Disabled (Web Only)</option>
                        <option value="fast" selected>Fast (Top 16 Ports)</option>
                        <option value="full">Full (1-65535)</option>
                    </select>
                </div>
            </div>

            <div>
                <span class="section-header">Configuration</span>
                <div class="input-group">
                    <label class="input-label">CONCURRENCY</label>
                    <input type="number" id="tThreads" value="50">
                </div>
                <div class="upload-box" id="dropZone" onclick="document.getElementById('fInput').click()">
                    <span id="fText" class="upload-label">CLICK TO UPLOAD WORDLIST</span>
                    <div class="file-reset" id="fReset" onclick="resetFile(event)">✕</div>
                    <input type="file" id="fInput">
                </div>
            </div>

            <div class="btn-group">
                <button class="btn btn-start" onclick="startScan()">INITIALIZE SYSTEM</button>
                <button class="btn btn-stop" onclick="stopScan()">ABORT SEQUENCE</button>
            </div>
        </div>

        <div class="content">
            <div class="tabs-container">
                <div class="tab active" onclick="setTab('ALL')">TOTAL FEED</div>
                <div class="tab" onclick="setTab('sub')">SUBDOMAINS</div>
                <div class="tab" onclick="setTab('dir')">DIRECTORIES</div>
                <div class="tab" onclick="setTab('port')">PORTS</div>
            </div>

            <div class="filter-bar">
                <span class="filter-title">FILTERS:</span>
                <div id="filterList" style="display:flex; gap:8px;"></div>
            </div>
            
            <div class="grid-container">
                <div class="grid-head">
                    <div>TYPE</div>
                    <div>VALUE</div>
                    <div>STATUS</div>
                    <div>IP ADDR</div>
                    <div>LATENCY</div>
                    <div>META INFO</div>
                </div>
                <div id="grid"></div>
            </div>
        </div>
    </div>

    <script>
        let currentScanId = null;
        let es = null;
        let activeTab = 'ALL';
        let db = []; // Master Database
        let modState = { sub: true, dir: true };
        
        let activeFilters = new Set();
        
        // Configuration for Auto-Filters
        const alwaysShow = ['200', 'OPEN', '301', '302', '403', 'DNS OK'];
        const defaultHidden = ['NXDOMAIN', 'CLOSED', 'ERR', 'REFUSED', 'TIMEOUT_C', 'TIMEOUT_R', 'DNS_TO', 'DNS_ERR'];

        function toggle(m) {
            modState[m] = !modState[m];
            const el = document.getElementById(m === 'sub' ? 'mSub' : 'mDir');
            el.classList.toggle('active');
        }

        // File Upload Handling
        const fInput = document.getElementById('fInput');
        const fText = document.getElementById('fText');
        const fZone = document.getElementById('dropZone');
        const fReset = document.getElementById('fReset');

        fInput.addEventListener('change', e => {
            if(e.target.files.length > 0) {
                fText.innerText = "READY: " + e.target.files[0].name;
                fText.style.color = "var(--success)";
                fZone.classList.add('active');
                fReset.style.display = 'block';
            }
        });

        function resetFile(e) {
            e.stopPropagation();
            fInput.value = '';
            fText.innerText = "CLICK TO UPLOAD WORDLIST";
            fText.style.color = "var(--text-muted)";
            fZone.classList.remove('active');
            fReset.style.display = 'none';
        }

        function setTab(t) {
            activeTab = t;
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            event.target.classList.add('active');
            recalcFiltersForTab();
            render(); 
        }

        function startScan() {
            const tInput = document.getElementById('tInput').value;
            if(!tInput) return alert("Target Required");

            const fd = new FormData();
            fd.append('target', tInput);
            fd.append('threads', document.getElementById('tThreads').value);
            
            const mods = { sub: modState.sub, dir: modState.dir, port: document.getElementById('mPort').value };
            fd.append('modules', JSON.stringify(mods));

            if(fInput.files.length > 0) fd.append('wordlist', fInput.files[0]);

            db = [];
            activeFilters.clear();
            document.getElementById('grid').innerHTML = '';
            document.getElementById('filterList').innerHTML = '';
            document.getElementById('pBar').style.width = '0%';
            
            fetch('/start', {method:'POST', body:fd})
            .then(r=>r.json()).then(d=>connect(d.scan_id));
        }

        function stopScan() {
            if(currentScanId) fetch(`/stop/${currentScanId}`);
            if(es) es.close();
        }

        function connect(id) {
            currentScanId = id;
            es = new EventSource(`/stream/${id}`);
            es.onmessage = e => {
                if(!e.data) return;
                const msg = JSON.parse(e.data);
                if(msg.type === 'done') es.close();
                else if(msg.type === 'info') document.getElementById('tIp').innerText = msg.data.ip;
                else if(msg.type === 'stats') {
                    document.getElementById('pBar').style.width = msg.data.progress + "%";
                    document.getElementById('tRps').innerText = msg.data.rps;
                    document.getElementById('tProg').innerText = `${msg.data.tasks} / ${msg.data.total}`;
                }
                else if(msg.type === 'result') {
                    db.push(msg.data);
                    // Only process/render if it belongs to current tab OR 'ALL'
                    if(activeTab === 'ALL' || msg.data.cat === activeTab) {
                        handleNewDataPoint(msg.data);
                        // Live rendering for performance: Check if filter active before appending
                        if(activeFilters.has(msg.data.code)) {
                            // Update count in existing chip? Too complex for vanilla JS live update.
                            // Just render filters occasionally or simple re-render.
                            // For smoothest experience: debounce re-render or just append row.
                            // Let's keep it simple: Re-render entire view is safe but maybe slow on massive data.
                            // Optimization: Append row if matches filter, update filter counts.
                            render(); // Keeps counts accurate
                        }
                    }
                }
            };
        }

        function handleNewDataPoint(d) {
            if (!activeFilters.has(d.code)) {
                if (alwaysShow.includes(d.code) || ['200','OPEN'].includes(d.code)) {
                    activeFilters.add(d.code);
                }
                else if (!defaultHidden.includes(d.code)) {
                    activeFilters.add(d.code);
                }
            }
        }

        function recalcFiltersForTab() {
            activeFilters.clear();
            const subset = activeTab === 'ALL' ? db : db.filter(d => d.cat === activeTab);
            
            subset.forEach(d => {
                if(alwaysShow.includes(d.code) || ['200','OPEN'].includes(d.code)) activeFilters.add(d.code);
                else if (!defaultHidden.includes(d.code)) activeFilters.add(d.code);
            });
        }

        function render() {
            const grid = document.getElementById('grid');
            grid.innerHTML = '';
            
            const subset = activeTab === 'ALL' ? db : db.filter(d => d.cat === activeTab);
            
            const counts = {};
            subset.forEach(d => {
                if(!counts[d.code]) counts[d.code] = 0;
                counts[d.code]++;
            });
            
            const box = document.getElementById('filterList');
            box.innerHTML = '';
            Object.keys(counts).sort().forEach(code => {
                const isActive = activeFilters.has(code);
                const chip = document.createElement('div');
                chip.className = `chip ${isActive ? 'active' : ''}`;
                chip.onclick = () => toggleFilter(code);
                chip.innerHTML = `${code} <span class="chip-badge">${counts[code]}</span>`;
                box.appendChild(chip);
            });
            
            const frag = document.createDocumentFragment();
            subset.forEach(d => {
                if(activeFilters.has(d.code)) {
                    frag.appendChild(createRow(d));
                }
            });
            grid.appendChild(frag);
        }

        function toggleFilter(code) {
            if(activeFilters.has(code)) activeFilters.delete(code);
            else activeFilters.add(code);
            render();
        }

        function createRow(d) {
            const row = document.createElement('div');
            
            let badgeClass = 'st-dim';
            if(['200','OPEN','DNS OK'].includes(d.code)) badgeClass = 'st-ok';
            else if(d.code === '403') badgeClass = 'st-warn';
            else if(d.code.startsWith('5') || d.code.includes('FAIL') || d.code.includes('REFUSED')) badgeClass = 'st-err';
            else if(d.code.startsWith('3')) badgeClass = 'st-info';

            row.className = 'row';
            
            let valHtml = d.val;
            if(d.link !== '#') valHtml = `<a href="${d.link}" target="_blank">${d.val}</a>`;

            row.innerHTML = `
                <div class="cell-cat">${d.cat}</div>
                <div class="cell-val">${valHtml}</div>
                <div><span class="status-pill ${badgeClass}">${d.code}</span></div>
                <div class="cell-ip">${d.ip}</div>
                <div class="cell-ip">${d.lat}</div>
                <div class="cell-meta">${d.meta}</div>
            `;
            return row;
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home(): return render_template_string(HTML_UI)

@app.route('/start', methods=['POST'])
def start():
    target = request.form.get('target')
    threads = request.form.get('threads', 50)
    try: modules = json.loads(request.form.get('modules'))
    except: modules = {'sub':True, 'dir':True, 'port':'fast'}

    wordlist = DEFAULT_WORDLIST
    if 'wordlist' in request.files:
        f = request.files['wordlist']
        if f.filename != '':
            try:
                content = f.read()
                try: text = content.decode('utf-8')
                except: text = content.decode('latin-1')
                custom = [x.strip() for x in text.splitlines() if x.strip()]
                if custom: wordlist = custom
            except: pass

    scan_id = str(uuid.uuid4())
    scanner = Scanner(scan_id, target, wordlist, threads, modules)
    scans[scan_id] = scanner
    
    t = threading.Thread(target=scanner.start)
    t.daemon = True
    t.start()
    return jsonify({"scan_id": scan_id})

@app.route('/stop/<scan_id>')
def stop(scan_id):
    if scan_id in scans: scans[scan_id].stop_event.set()
    return jsonify({"status": "stopped"})

@app.route('/stream/<scan_id>')
def stream(scan_id):
    def gen():
        scanner = scans.get(scan_id)
        if not scanner: return
        while True:
            try:
                msg = scanner.msg_queue.get(timeout=0.5)
                yield f"data: {msg}\n\n"
            except queue.Empty:
                if getattr(scanner, 'finished', False): break
                yield ": keep-alive\n\n"
    return Response(stream_with_context(gen()), mimetype="text/event-stream")

if __name__ == '__main__':
    print("Aegis V16 Zenith UI Running on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, threaded=True)
