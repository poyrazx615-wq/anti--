# Kali Security Platform

<div align="center">
  <h1>🛡️ Kali Security Platform</h1>
  <p><strong>130+ Security Tools | Web Interface | Real-time Execution</strong></p>
  
  ![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
  ![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)
  ![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)
  ![Tools](https://img.shields.io/badge/Tools-130+-red.svg)
  ![License](https://img.shields.io/badge/License-Educational-yellow.svg)
</div>

## 🎯 Features

- **130+ Security Tools** - Comprehensive collection of penetration testing tools
- **Web-based Terminal** - Execute commands directly from browser
- **OSINT Framework** - 17+ OSINT tools with usage scenarios
- **Exploit Advisor** - Automated exploit recommendations
- **PDF Reports** - Professional penetration testing reports
- **Real-time Output** - Live command execution streaming
- **Dark Mode** - Eye-friendly interface
- **SQLite Database** - Persistent storage of scan results

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
# Clone the repository
git clone https://github.com/yourusername/kali-security-platform.git
cd kali-security-platform

# Build and run with Docker
docker-compose up -d

# Access the platform
http://localhost:8000
```

### Option 2: Manual Installation
```bash
# Run installation script
chmod +x install.sh
./install.sh

# Activate virtual environment
source venv/bin/activate

# Start the platform
python main.py
```

### Option 3: Manual Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Run the application
python main.py
```

## 📋 Available Tools

### Web Security (15+ tools)
- Nuclei, OWASP ZAP, FFuF, Wfuzz, Gobuster
- Commix, XSStrike, NoSQLMap, GitTools

### Network Exploitation (15+ tools)
- Responder, CrackMapExec, Impacket, BloodHound
- Evil-WinRM, LinPEAS, WinPEAS, Mimikatz

### Password Cracking (5+ tools)
- Hashcat, John the Ripper, Hydra, CeWL, JWT_Tool

### Wireless Security (5+ tools)
- Wifite2, Bettercap, Kismet, Aircrack-ng

### Cloud Security (5+ tools)
- ScoutSuite, Prowler, Pacu, CloudSploit

### Mobile Security (5+ tools)
- MobSF, Frida, Objection, APKTool, JADX

### Forensics (5+ tools)
- Volatility3, Autopsy, Binwalk, Wireshark, Foremost

### Reverse Engineering (5+ tools)
- Ghidra, Radare2, GDB, IDA Pro, x64dbg

### OSINT (17+ tools)
- Shodan, Censys, Amass, theHarvester, Sherlock
- SpiderFoot, Maltego, Recon-ng, PhoneInfoga

## 🖥️ Web Interface

### Dashboard
- Real-time statistics
- Active scan monitoring
- Quick access to all tools

### Security Tools Page
- Search and filter 130+ tools
- Category-based organization
- Platform filtering (Linux/Windows/macOS)
- Integrated web terminal
- Command history and auto-completion

### OSINT Framework
- Organized OSINT tools
- Usage scenarios
- Step-by-step workflows

### Exploit Advisor
- Vulnerability-based exploit recommendations
- Attack vectors and success rates
- Command examples

## 📚 Usage Examples

### Running a Tool
1. Navigate to Security Tools page
2. Search or select a tool
3. View usage examples
4. Execute in web terminal
5. Save output or generate report

### Creating a Workflow
1. Click "Workflows" button
2. Select target type (Web, Network, AD, etc.)
3. Follow recommended tool sequence
4. Execute each phase

### Generating Reports
1. Complete your scans
2. Click "Export PDF" button
3. Comprehensive report with all findings

## 🔧 Configuration

Edit `.env` file for customization:

```env
# Server Settings
HOST=0.0.0.0
PORT=8000

# API Keys (Optional)
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here

# Features
ENABLE_TOOL_EXECUTION=true
ENABLE_DOCKER_EXECUTION=true
```

## 🐳 Docker Deployment

### Build Custom Image
```bash
docker build -t kali-security-platform .
```

### Run with Docker Compose
```bash
docker-compose up -d
```

### Access Services
- Main Platform: http://localhost:8000
- OWASP ZAP: http://localhost:8090
- PostgreSQL: localhost:5432
- Redis: localhost:6379

## 📊 API Documentation

### List All Tools
```bash
GET /api/security-tools/list
```

### Get Tool Details
```bash
GET /api/security-tools/tool/{tool_name}
```

### Execute Command
```bash
POST /api/security-tools/execute
{
  "command": "nmap -sV target.com",
  "tool": "nmap"
}
```

### Generate PDF Report
```bash
GET /api/security-tools/export-pdf
```

## 🔒 Security Notes

⚠️ **WARNING**: This platform is for educational and authorized testing only!

- Never use on systems without explicit permission
- Some tools require root/admin privileges
- Use Docker for isolation when possible
- Keep API keys secure and never commit to git

## 🎓 Educational Use

Perfect for:
- Cybersecurity training
- Penetration testing courses
- CTF competitions
- Security research
- Bug bounty hunting

## 📝 License

This project is for educational purposes only. Users are responsible for complying with all applicable laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

<div align="center">
  <strong>Built with ❤️ for the security community</strong>
  <br>
  <em>Stay ethical, stay legal, stay safe!</em>
</div>