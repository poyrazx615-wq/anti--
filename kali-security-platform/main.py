#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kali Security Platform - Main Application
Full Featured Version with 130+ Tools
"""

import uvicorn
import os
import sys
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import asyncio
import json
from typing import Dict, Optional
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import vulnerability analyzer
from core.vulnerability_analyzer import vulnerability_analyzer

# Create FastAPI app
app = FastAPI(
    title="Kali Security Platform",
    description="Professional Penetration Testing Framework with 130+ Tools",
    version="5.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create necessary directories
Path("outputs").mkdir(exist_ok=True)
Path("logs").mkdir(exist_ok=True)
Path("templates").mkdir(exist_ok=True)

# Import all routes
try:
    from api.routes import exploit_advisor, osint, security_tools
    
    # Include all routers
    app.include_router(security_tools.router, prefix="/api/security-tools", tags=["Security Tools"])
    app.include_router(osint.router, prefix="/api/osint", tags=["OSINT"])
    app.include_router(exploit_advisor.router, prefix="/api/exploit-advisor", tags=["Exploit Advisor"])
    print("[+] All routes loaded successfully!")
except ImportError as e:
    print(f"[!] Warning: Could not import some routes: {e}")

# Store for scan results
scan_results = {}

# Store vulnerability reports
vulnerability_reports = {}

# ============================================
# UTILITY FUNCTIONS FOR REAL TOOL EXECUTION
# ============================================

async def execute_tool(command: str, timeout: int = 30) -> Dict:
    """Execute security tools safely"""
    try:
        # Security check
        allowed_tools = [
            "nmap", "nikto", "sqlmap", "dirb", "gobuster", "hydra",
            "dig", "host", "whois", "dnsrecon", "amass", "subfinder",
            "curl", "wget", "netdiscover", "arp-scan", "masscan",
            "enum4linux", "smbclient", "metasploit", "searchsploit"
        ]
        
        tool = command.split()[0]
        if tool not in allowed_tools:
            return {"success": False, "error": f"Tool '{tool}' not allowed for security reasons"}
        
        # Execute command
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), 
            timeout=timeout
        )
        
        return {
            "success": True,
            "output": stdout.decode('utf-8', errors='ignore'),
            "error": stderr.decode('utf-8', errors='ignore'),
            "command": command
        }
    except asyncio.TimeoutError:
        return {"success": False, "error": f"Command timed out after {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ============================================
# MAIN DASHBOARD PAGE
# ============================================

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Ana dashboard - URL tarama özellikli"""
    return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali Security Platform - 130+ Security Tools</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .glass-effect {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .terminal {
            background: #0f0f23;
            color: #10ff00;
            font-family: 'Courier New', monospace;
        }
        .scan-button {
            background: linear-gradient(90deg, #00d2ff 0%, #3a47d5 100%);
            transition: all 0.3s ease;
        }
        .scan-button:hover {
            transform: scale(1.05);
            box-shadow: 0 10px 40px rgba(0, 210, 255, 0.4);
        }
    </style>
</head>
<body class="gradient-bg min-h-screen text-white">
    <!-- Navigation -->
    <nav class="glass-effect border-b border-white/20">
        <div class="container mx-auto px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                    <i class="fas fa-shield-alt text-3xl text-purple-400"></i>
                    <h1 class="text-2xl font-bold">Kali Security Platform v5.0</h1>
                </div>
                <div class="flex space-x-6">
                    <a href="/" class="text-purple-300">Dashboard</a>
                    <a href="/security-tools" class="hover:text-purple-300 transition">Security Tools</a>
                    <a href="/osint" class="hover:text-purple-300 transition">OSINT</a>
                    <a href="/exploit-advisor" class="hover:text-purple-300 transition">Exploits</a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="container mx-auto px-6 py-8">
        <!-- Quick Scan Section -->
        <div class="glass-effect rounded-2xl p-8 mb-8">
            <h2 class="text-3xl font-bold mb-6 text-center">
                <i class="fas fa-crosshairs text-yellow-400"></i> Quick Security Scanner
            </h2>
            
            <!-- URL/IP Input -->
            <div class="flex space-x-4 mb-6">
                <input type="text" id="target-input" 
                       placeholder="Enter URL, IP or Domain (e.g., example.com, 192.168.1.1)" 
                       class="flex-1 px-6 py-4 text-lg text-gray-900 rounded-xl focus:outline-none focus:ring-4 focus:ring-purple-400">
                
                <select id="scan-type" class="px-6 py-4 text-gray-900 rounded-xl">
                    <option value="quick">Quick Scan</option>
                    <option value="full">Full Scan</option>
                    <option value="web">Web Vuln Scan</option>
                    <option value="network">Network Scan</option>
                    <option value="osint">OSINT Recon</option>
                </select>
                
                <button onclick="startQuickScan()" class="scan-button text-white px-8 py-4 rounded-xl font-bold text-lg">
                    <i class="fas fa-rocket"></i> Start Scan
                </button>
            </div>

            <!-- Progress Bar -->
            <div id="scan-progress" class="hidden mb-6">
                <div class="bg-gray-700 rounded-full h-3">
                    <div id="progress-bar" class="bg-gradient-to-r from-green-400 to-blue-500 h-3 rounded-full transition-all duration-500" style="width: 0%"></div>
                </div>
                <p class="text-center mt-2 text-sm">Scanning in progress...</p>
            </div>

            <!-- Terminal Output -->
            <div class="terminal rounded-xl p-4 h-64 overflow-y-auto mb-6" id="terminal-output">
                <div class="text-green-400">
                    <span>$ Welcome to Kali Security Platform</span><br>
                    <span>$ Ready for scanning...</span><br>
                    <span class="text-gray-500">Enter a target above and click Start Scan</span>
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="grid grid-cols-5 gap-4">
                <button onclick="quickScan('nmap')" class="bg-blue-600 hover:bg-blue-700 p-3 rounded-lg transition">
                    <i class="fas fa-network-wired"></i> Port Scan
                </button>
                <button onclick="quickScan('nikto')" class="bg-green-600 hover:bg-green-700 p-3 rounded-lg transition">
                    <i class="fas fa-spider"></i> Web Scan
                </button>
                <button onclick="quickScan('sqlmap')" class="bg-red-600 hover:bg-red-700 p-3 rounded-lg transition">
                    <i class="fas fa-database"></i> SQL Test
                </button>
                <button onclick="quickScan('dns')" class="bg-purple-600 hover:bg-purple-700 p-3 rounded-lg transition">
                    <i class="fas fa-globe"></i> DNS Enum
                </button>
                <button onclick="quickScan('osint')" class="bg-orange-600 hover:bg-orange-700 p-3 rounded-lg transition">
                    <i class="fas fa-user-secret"></i> OSINT
                </button>
            </div>
        </div>

        <!-- Stats Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="glass-effect rounded-xl p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-300 text-sm">Total Tools</p>
                        <p class="text-3xl font-bold mt-2">130+</p>
                    </div>
                    <i class="fas fa-tools text-4xl text-purple-400"></i>
                </div>
            </div>

            <div class="glass-effect rounded-xl p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-300 text-sm">OSINT Tools</p>
                        <p class="text-3xl font-bold mt-2">17</p>
                    </div>
                    <i class="fas fa-search text-4xl text-blue-400"></i>
                </div>
            </div>

            <div class="glass-effect rounded-xl p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-300 text-sm">Exploits DB</p>
                        <p class="text-3xl font-bold mt-2">Ready</p>
                    </div>
                    <i class="fas fa-bomb text-4xl text-red-400"></i>
                </div>
            </div>

            <div class="glass-effect rounded-xl p-6">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-gray-300 text-sm">Status</p>
                        <p class="text-3xl font-bold mt-2 text-green-400">Active</p>
                    </div>
                    <i class="fas fa-check-circle text-4xl text-green-400"></i>
                </div>
            </div>
        </div>

        <!-- Tool Categories -->
        <div class="glass-effect rounded-xl p-6">
            <h3 class="text-xl font-semibold mb-4">Security Tool Categories</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <a href="/security-tools" class="bg-purple-600 hover:bg-purple-700 p-4 rounded-lg text-center transition">
                    <i class="fas fa-terminal text-2xl mb-2"></i>
                    <p>Security Tools</p>
                </a>
                <a href="/osint" class="bg-blue-600 hover:bg-blue-700 p-4 rounded-lg text-center transition">
                    <i class="fas fa-user-secret text-2xl mb-2"></i>
                    <p>OSINT Framework</p>
                </a>
                <a href="/exploit-advisor" class="bg-red-600 hover:bg-red-700 p-4 rounded-lg text-center transition">
                    <i class="fas fa-bug text-2xl mb-2"></i>
                    <p>Exploit Advisor</p>
                </a>
                <a href="/security-tools" class="bg-green-600 hover:bg-green-700 p-4 rounded-lg text-center transition">
                    <i class="fas fa-shield-alt text-2xl mb-2"></i>
                    <p>Forensics</p>
                </a>
            </div>
        </div>
    </div>

    <script>
        let scanInterval = null;
        let progress = 0;

        async function startQuickScan() {
            const target = document.getElementById('target-input').value;
            const scanType = document.getElementById('scan-type').value;
            
            if (!target) {
                alert('Please enter a target URL, IP or domain!');
                return;
            }

            // Show progress
            document.getElementById('scan-progress').classList.remove('hidden');
            progress = 0;
            
            // Update terminal
            const terminal = document.getElementById('terminal-output');
            terminal.innerHTML = `<span class="text-yellow-400">$ Starting ${scanType} scan on ${target}...</span><br>`;
            
            // Animate progress
            scanInterval = setInterval(() => {
                progress = Math.min(progress + Math.random() * 15, 95);
                document.getElementById('progress-bar').style.width = progress + '%';
            }, 500);

            try {
                const response = await fetch('/api/quick-scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        target: target,
                        scan_type: scanType
                    })
                });

                const data = await response.json();
                displayResults(data);
            } catch (error) {
                terminal.innerHTML += `<span class="text-red-400">Error: ${error.message}</span><br>`;
            } finally {
                clearInterval(scanInterval);
                document.getElementById('progress-bar').style.width = '100%';
                setTimeout(() => {
                    document.getElementById('scan-progress').classList.add('hidden');
                }, 2000);
            }
        }

        async function quickScan(tool) {
            const target = document.getElementById('target-input').value || 'scanme.nmap.org';
            document.getElementById('target-input').value = target;
            
            const terminal = document.getElementById('terminal-output');
            terminal.innerHTML = `<span class="text-yellow-400">$ Running ${tool} scan on ${target}...</span><br>`;
            
            try {
                const response = await fetch('/api/tool-execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        tool: tool,
                        target: target
                    })
                });

                const data = await response.json();
                displayResults(data);
            } catch (error) {
                terminal.innerHTML += `<span class="text-red-400">Error: ${error.message}</span>`;
            }
        }

        function displayResults(data) {
            const terminal = document.getElementById('terminal-output');
            
            if (data.success) {
                terminal.innerHTML += `<span class="text-green-400">$ Scan completed successfully!</span><br><br>`;
                if (data.output) {
                    terminal.innerHTML += `<pre class="text-gray-300">${data.output}</pre>`;
                }
            } else {
                terminal.innerHTML += `<span class="text-red-400">$ Error: ${data.error}</span><br>`;
            }
            
            terminal.scrollTop = terminal.scrollHeight;
        }
    </script>
</body>
</html>
    """)

# ============================================
# API ENDPOINTS FOR SCANNING
# ============================================

@app.post("/api/quick-scan")
async def quick_scan(request: Dict):
    """Quick scan with automatic tool selection"""
    target = request.get("target", "")
    scan_type = request.get("scan_type", "quick")
    
    if not target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    # Clean target
    target = target.replace("http://", "").replace("https://", "").split('/')[0]
    
    # Select appropriate command based on scan type
    commands = {
        "quick": f"nmap -F {target}",
        "full": f"nmap -sV -sC -O {target}",
        "web": f"nikto -h http://{target} -Tuning 123 -maxtime 60s",
        "network": f"nmap -sn {target}/24",
        "osint": f"whois {target}"
    }
    
    command = commands.get(scan_type, commands["quick"])
    result = await execute_tool(command, timeout=60)
    
    # Store results
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_results[scan_id] = {
        "target": target,
        "type": scan_type,
        "timestamp": datetime.now().isoformat(),
        "result": result
    }
    
    return result

@app.post("/api/vulnerability-analysis")
async def vulnerability_analysis(request: Dict):
    """Zafiyet analizi ve exploit önerileri"""
    target = request.get("target", "")
    scan_results_text = request.get("scan_results", "")
    
    if not target or not scan_results_text:
        raise HTTPException(status_code=400, detail="Target and scan results required")
    
    # Analyze vulnerabilities
    report = vulnerability_analyzer.generate_detailed_report(scan_results_text, target)
    
    # Store report
    report_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    vulnerability_reports[report_id] = report
    
    return {
        "report_id": report_id,
        "vulnerabilities": report["vulnerabilities"],
        "attack_plan": report["attack_plan"],
        "risk_score": report["risk_score"],
        "recommendations": report["recommendations"]
    }

@app.get("/api/exploit-guide/{vulnerability_type}")
async def get_exploit_guide(vulnerability_type: str):
    """Specific vulnerability exploit guide"""
    exploit_info = vulnerability_analyzer.get_exploit_recommendations(vulnerability_type)
    
    if not exploit_info:
        raise HTTPException(status_code=404, detail="Exploit guide not found")
    
    return exploit_info

@app.post("/api/tool-execute")
async def tool_execute(request: Dict):
    """Execute specific tool"""
    tool = request.get("tool", "")
    target = request.get("target", "")
    
    if not tool or not target:
        raise HTTPException(status_code=400, detail="Tool and target are required")
    
    # Clean target
    target = target.replace("http://", "").replace("https://", "").split('/')[0]
    
    # Tool commands
    tool_commands = {
        "nmap": f"nmap -sV {target}",
        "nikto": f"nikto -h http://{target} -maxtime 60s",
        "sqlmap": f"sqlmap -u http://{target} --batch --forms --crawl=2 --level=1",
        "dns": f"dnsrecon -d {target}",
        "osint": f"theHarvester -d {target} -b all"
    }
    
    command = tool_commands.get(tool)
    if not command:
        raise HTTPException(status_code=400, detail=f"Unknown tool: {tool}")
    
    result = await execute_tool(command, timeout=60)
    return result

# ============================================
# TOOL PAGES
# ============================================

@app.get("/security-tools", response_class=HTMLResponse)
async def security_tools_page():
    """Security tools page"""
    return HTMLResponse(content=open("api/routes/security_tools.py").read().split('HTML_CONTENT = """')[1].split('"""')[0])

@app.get("/osint", response_class=HTMLResponse)
async def osint_page():
    """OSINT page"""
    return HTMLResponse(content=open("api/routes/osint.py").read().split('HTML_CONTENT = """')[1].split('"""')[0])

@app.get("/exploit-advisor", response_class=HTMLResponse)
async def exploit_advisor_page():
    """Exploit advisor page"""
    return HTMLResponse(content=open("api/routes/exploit_advisor.py").read().split('HTML_CONTENT = """')[1].split('"""')[0])

@app.get("/vulnerability-analysis", response_class=HTMLResponse)
async def vulnerability_analysis_page():
    """Vulnerability analysis and attack advisory page"""
    return HTMLResponse(content=open("templates/vulnerability_analysis.html").read())

# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "5.0.0",
        "tools_count": 130,
        "active_scans": len(scan_results)
    }

# ============================================
# MAIN EXECUTION
# ============================================

if __name__ == "__main__":
    # Get environment variables
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    reload = os.getenv("RELOAD", "false").lower() == "true"
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     KALI SECURITY PLATFORM v5.0                             ║
    ║     130+ Security Tools | OSINT | Exploits | Forensics      ║
    ╚══════════════════════════════════════════════════════════════╝
    
    [+] Starting Kali Security Platform...
    [+] Host: {host}
    [+] Port: {port}
    
    [!] Access the platform at: http://localhost:{port}
    
    Available Pages:
    → Dashboard:       http://localhost:{port}/
    → Security Tools:  http://localhost:{port}/security-tools
    → OSINT Tools:     http://localhost:{port}/osint
    → Exploit Advisor: http://localhost:{port}/exploit-advisor
    
    Press CTRL+C to stop the server.
    """.format(host=host, port=port))
    
    # Run the application
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )
