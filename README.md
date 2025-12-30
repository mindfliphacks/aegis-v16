# Aegis V16 Zenith 🛡️

A streamlined, web-based reconnaissance tool designed for modern security assessments. Aegis combines subdomain enumeration, directory brute-forcing, and port scanning into a single, responsive interface with real-time reporting.

## ✨ Features

* **Unified Web Interface:** A single dashboard to control scans and view results.
* **Multi-Module Scanning:**
    * **Subdomain Enumeration:** DNS resolution and HTTP probing.
    * **Directory Discovery:** Fuzzing for common paths (admin, backup, git, etc.).
    * **Port Scanning:** Fast (Top 16 ports) or Full (1-65535) TCP scanning.
* **Smart Probing:** Automatically detects HTTP vs HTTPS and handles redirects.
* **Real-Time Feedback:** Uses Server-Sent Events (SSE) to stream results without page reloads.
* **Live Filtering:** Filter results by status code (200, 403, 500) or category instantly.
* **Concurrency:** Multi-threaded architecture supporting high request rates.

## 🚀 Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/mindfliphacks/aegis-v16.git
    cd aegis-v16
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application**
    ```bash
    python aegis.py
    ```

4.  **Access the Dashboard**
    Open your browser and navigate to:
    `http://127.0.0.1:5000`

## 📖 Usage

1.  **Target Scope:** Enter the domain URL (e.g., `example.com`).
2.  **Modules:** Toggle Subdomain or Directory modules on/off.
3.  **Port Scan:** Select "Fast" (Top ports), "Full", or "Disabled".
4.  **Concurrency:** Set thread count (Default: 50).
5.  **Wordlist:** (Optional) Upload a custom `.txt` wordlist. If skipped, Aegis uses a built-in default list.
6.  **Start:** Click "Initialize System" to begin.

## ⚠️ Disclaimer

This tool is designed for **educational purposes and authorized security testing only**. You must have explicit permission from the system owner before scanning any target. The author is not responsible for any misuse or damage caused by this program.

## 📜 License

MIT License
