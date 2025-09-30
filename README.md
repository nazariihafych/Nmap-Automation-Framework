<div align="center" style="max-width: 800px; margin: 0 auto; padding: 20px; background-color: #0D1117; color: #C9D1D9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; border-radius: 16px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); line-height: 1.6;">
  <img src="https://github.com/user-attachments/assets/bf3b6c99-52f8-4718-a704-4874d331bf50"
       width="203"
       style="border-radius: 50%; border: 4px solid #58A6FF; margin: 30px 0; box-shadow: 0 4px 8px rgba(88, 166, 255, 0.5);"
       alt="Nmap Automation Framework Logo" />

  <h1 style="color: #FFFFFF; margin: 20px 0;">Nmap Automation Framework</h1>

  <p><strong>Nmap Automation Framework</strong> is an enhanced Python script for automating network scanning using <code>nmap</code>. Designed for ethical hackers, system administrators, and cybersecurity professionals, it supports asynchronous and scheduled scans, remote control via API, encrypted result storage, and Telegram notifications.</p>

  <h2 style="color: #58A6FF; margin-top: 30px;">Key Features</h2>
  <ul style="text-align: left; padding-left: 20px;">
    <li>Asynchronous and scheduled scanning (including SYN, TCP, UDP, OS detection, Aggressive, and Ping scans).</li>
    <li>RESTful API for remote scan execution built with Quart (asynchronous Flask).</li>
    <li>Results encryption using AES (via Fernet) and secure storage in encrypted files.</li>
    <li>Telegram notifications upon scan completion or errors.</li>
    <li>Flexible configuration via environment variables and API parameters.</li>
    <li>Comprehensive logging for monitoring and diagnostics.</li>
    <li>Input validation for IP addresses, CIDR ranges, and domain names.</li>
  </ul>

  <h2 style="color: #58A6FF; margin-top: 30px;">Installation</h2>
  <ol style="text-align: left; padding-left: 20px;">
    <li>Clone the repository:
      <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>git clone https://github.com/nazariihafych/Nmap-Automation-Framework.git
cd Nmap-Automation-Framework</code></pre>
    </li>
    <li>Install dependencies:
      <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>pip install -r requirements.txt</code></pre>
    </li>
    <li>Create a <code>.env</code> file in the project root:
      <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id
FERNET_KEY=your_44_char_fernet_key_here
INITIAL_TASKS=[{"target":"192.168.1.1","scan_type":"TCP","interval":30}]

# Nmap settings
NMAP_HOST_TIMEOUT_SEC=300
NMAP_MAX_RETRIES=2</code></pre>
    </li>
  </ol>

  <h2 style="color: #58A6FF; margin-top: 30px;">Quick Start</h2>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto;"><code>python scan_automation.py</code></pre>

  <h2 style="color: #58A6FF; margin-top: 30px;">Remote API Control</h2>
  <h3>Run an Immediate Scan</h3>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto;"><code>curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "TCP"}'</code></pre>

  <h3>Schedule a Periodic Scan</h3>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto;"><code>curl -X POST http://localhost:5000/schedule \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "SYN", "interval": 30}'</code></pre>

  <h2 style="color: #58A6FF; margin-top: 30px;">Encryption & Decryption</h2>
  <p>All scan results are automatically saved in encrypted form (using Fernet symmetric encryption) in the <code>encrypted_results/</code> directory.</p>

  <p>To decrypt a file, use the provided <code>decrypt.py</code> script:</p>

  <h3>1. Ensure <code>.env</code> contains your key</h3>
  <p>The same <code>FERNET_KEY</code> used during scanning must be present in your <code>.env</code> file:</p>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code># .env
FERNET_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz1234=</code></pre>

  <h3>2. Run the decryption script</h3>
  <p>Pass the encrypted filename as an argument:</p>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code># Decrypt and print to terminal
python decrypt.py encrypted_results/192.168.1.1_TCP_20240510_120000.json

# Or save to a readable file
python decrypt.py encrypted_results/192.168.1.1_TCP_20240510_120000.json -o result.json</code></pre>

  <p>💡 <strong>Important:</strong> Never lose your <code>FERNET_KEY</code>! Without it, encrypted results <strong>cannot be recovered</strong>.</p>

  <h2 style="color: #58A6FF; margin-top: 30px;">Requirements</h2>
  <ul style="text-align: left; padding-left: 20px;">
    <li>Python 3.7+</li>
    <li><code>nmap</code> installed and available in your system PATH</li>
  </ul>
  <pre style="background: #161B22; color: #C9D1D9; padding: 12px; border-radius: 6px; overflow-x: auto; margin: 10px 0;"><code>sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS</code></pre>

  <h2 style="color: #58A6FF; margin-top: 30px;">Project Structure</h2>
  <ul style="text-align: left; padding-left: 20px; font-family: monospace;">
    <li><code>scan_automation.py</code> — main application script</li>
    <li><code>decrypt.py</code> — utility to decrypt scan results</li>
    <li><code>encrypted_results/</code> — directory for encrypted scan results</li>
    <li><code>scan_log.txt</code> — activity and error log file</li>
    <li><code>requirements.txt</code> — Python dependencies</li>
    <li><code>.env</code> — sensitive configuration (tokens, keys)</li>
  </ul>

  <h2 style="color: #FF7B72; margin-top: 30px;">⚠️ Important: Ethical Use Only</h2>
  <p>This tool is intended <strong>strictly for authorized security testing</strong> on networks you own or have explicit written permission to scan. Unauthorized scanning may violate laws in your jurisdiction.</p>
  <p style="font-style: italic; color: #8B949E;">
    This software is provided "AS IS", WITHOUT WARRANTIES OF ANY KIND.<br>
    The author disclaims all liability for misuse, damages, or consequences arising from its use.
  </p>
</div>
