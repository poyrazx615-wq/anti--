#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Complete Security Tools Integration Module - Part 3
Password Cracking, Wireless, Cloud Security, and Mobile Tools
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from .web_security import SecurityTool

class PasswordCrackingTools:
    """Password Cracking and Cryptography Tools"""
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        return {
            "HASHCAT": SecurityTool(
                name="Hashcat",
                category="Password Cracking",
                subcategory="GPU-based Cracker",
                description="World's fastest and most advanced password recovery tool",
                installation={
                    "linux": "apt-get install hashcat",
                    "windows": "Download from https://hashcat.net/hashcat/",
                    "macos": "brew install hashcat"
                },
                usage=[
                    "hashcat -m 0 -a 0 hash.txt wordlist.txt",
                    "hashcat -m 1000 -a 0 ntlm.txt rockyou.txt",
                    "hashcat -m 5600 -a 0 netntlmv2.txt wordlist.txt -r rules/best64.rule"
                ],
                examples=[
                    {
                        "description": "MD5 dictionary attack",
                        "command": "hashcat -m 0 -a 0 md5.txt /usr/share/wordlists/rockyou.txt"
                    },
                    {
                        "description": "NTLM with rules",
                        "command": "hashcat -m 1000 -a 0 ntlm.txt wordlist.txt -r rules/best64.rule"
                    },
                    {
                        "description": "WPA2 crack",
                        "command": "hashcat -m 22000 -a 0 wpa2.hccapx wordlist.txt"
                    },
                    {
                        "description": "Brute force mask",
                        "command": "hashcat -m 0 -a 3 hash.txt ?u?l?l?l?l?d?d?d"
                    },
                    {
                        "description": "Combination attack",
                        "command": "hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt"
                    },
                    {
                        "description": "Show cracked passwords",
                        "command": "hashcat -m 0 hash.txt --show"
                    }
                ],
                options=[
                    {"flag": "-m", "description": "Hash type"},
                    {"flag": "-a", "description": "Attack mode"},
                    {"flag": "-r", "description": "Rules file"},
                    {"flag": "-o", "description": "Output file"},
                    {"flag": "--show", "description": "Show cracked"},
                    {"flag": "-O", "description": "Optimized kernel"},
                    {"flag": "-w", "description": "Workload profile"},
                    {"flag": "--force", "description": "Force run"}
                ],
                output_format="txt",
                requires_root=False,
                api_support=False,
                gui_available=True,
                platform=["linux", "windows", "macos"],
                dependencies=["OpenCL/CUDA drivers"],
                documentation="https://hashcat.net/wiki/",
                github="https://github.com/hashcat/hashcat",
                alternatives=["John the Ripper", "Hydra", "RainbowCrack"]
            ),
            
            "CEWL": SecurityTool(
                name="CeWL",
                category="Password Cracking",
                subcategory="Wordlist Generator",
                description="Custom Word List generator",
                installation={
                    "linux": "apt-get install cewl",
                    "gem": "gem install cewl"
                },
                usage=[
                    "cewl https://target.com",
                    "cewl https://target.com -d 2 -m 5 -w wordlist.txt",
                    "cewl https://target.com --with-numbers"
                ],
                examples=[
                    {
                        "description": "Basic wordlist generation",
                        "command": "cewl https://example.com -w wordlist.txt"
                    },
                    {
                        "description": "With depth and minimum length",
                        "command": "cewl https://example.com -d 3 -m 6 -w wordlist.txt"
                    },
                    {
                        "description": "Include numbers",
                        "command": "cewl https://example.com --with-numbers -w wordlist.txt"
                    },
                    {
                        "description": "Email extraction",
                        "command": "cewl https://example.com -e --email_file emails.txt"
                    },
                    {
                        "description": "With authentication",
                        "command": "cewl https://example.com -a username:password"
                    }
                ],
                options=[
                    {"flag": "-d", "description": "Depth to spider"},
                    {"flag": "-m", "description": "Minimum word length"},
                    {"flag": "-w", "description": "Write output"},
                    {"flag": "-e", "description": "Include emails"},
                    {"flag": "--with-numbers", "description": "Include numbers"},
                    {"flag": "-a", "description": "Authentication"}
                ],
                output_format="txt",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "macos"],
                dependencies=["ruby"],
                documentation="https://github.com/digininja/CeWL",
                github="https://github.com/digininja/CeWL",
                alternatives=["crunch", "cupp", "maskprocessor"]
            ),
            
            "JWT_TOOL": SecurityTool(
                name="jwt_tool",
                category="Password Cracking",
                subcategory="JWT Testing",
                description="Toolkit for testing, tweaking and cracking JSON Web Tokens",
                installation={
                    "linux": "git clone https://github.com/ticarpi/jwt_tool && cd jwt_tool && python3 -m pip install -r requirements.txt",
                    "pip": "pip install jwt_tool"
                },
                usage=[
                    "python3 jwt_tool.py <JWT>",
                    "python3 jwt_tool.py <JWT> -X a",
                    "python3 jwt_tool.py <JWT> -C -d wordlist.txt"
                ],
                examples=[
                    {
                        "description": "Decode JWT",
                        "command": "python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
                    },
                    {
                        "description": "None algorithm attack",
                        "command": "python3 jwt_tool.py <JWT> -X a"
                    },
                    {
                        "description": "Key confusion attack",
                        "command": "python3 jwt_tool.py <JWT> -X k -pk public.pem"
                    },
                    {
                        "description": "Crack weak secret",
                        "command": "python3 jwt_tool.py <JWT> -C -d rockyou.txt"
                    },
                    {
                        "description": "Tamper and sign",
                        "command": "python3 jwt_tool.py <JWT> -T -S hs256 -p 'secret123'"
                    }
                ],
                options=[
                    {"flag": "-X", "description": "Exploit mode"},
                    {"flag": "-C", "description": "Crack mode"},
                    {"flag": "-T", "description": "Tamper mode"},
                    {"flag": "-S", "description": "Signing algorithm"},
                    {"flag": "-p", "description": "Secret/password"},
                    {"flag": "-d", "description": "Dictionary file"}
                ],
                output_format="txt",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["python3"],
                documentation="https://github.com/ticarpi/jwt_tool",
                github="https://github.com/ticarpi/jwt_tool",
                alternatives=["jwtcrack", "c-jwt-cracker"]
            )
        }

class WirelessTools:
    """Wireless Security Testing Tools"""
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        return {
            "WIFITE2": SecurityTool(
                name="Wifite2",
                category="Wireless",
                subcategory="Automated WiFi Attack",
                description="Automated wireless attack tool",
                installation={
                    "linux": "git clone https://github.com/derv82/wifite2.git && cd wifite2 && python3 setup.py install",
                    "apt": "apt-get install wifite"
                },
                usage=[
                    "wifite",
                    "wifite --kill",
                    "wifite -e ESSID",
                    "wifite --wps-only"
                ],
                examples=[
                    {
                        "description": "Automated scan and attack",
                        "command": "wifite --kill"
                    },
                    {
                        "description": "Target specific network",
                        "command": "wifite -e 'TargetNetwork'"
                    },
                    {
                        "description": "WPS attacks only",
                        "command": "wifite --wps-only --pixie"
                    },
                    {
                        "description": "WPA handshake capture",
                        "command": "wifite --no-wps --no-pmkid"
                    },
                    {
                        "description": "Use specific wordlist",
                        "command": "wifite --dict /path/to/wordlist.txt"
                    }
                ],
                options=[
                    {"flag": "--kill", "description": "Kill conflicting processes"},
                    {"flag": "-e", "description": "Target ESSID"},
                    {"flag": "--wps-only", "description": "Only WPS attacks"},
                    {"flag": "--no-wps", "description": "Skip WPS attacks"},
                    {"flag": "--dict", "description": "Dictionary file"},
                    {"flag": "--pixie", "description": "Use PixieDust attack"}
                ],
                output_format="txt/cap",
                requires_root=True,
                api_support=False,
                gui_available=False,
                platform=["linux"],
                dependencies=["aircrack-ng", "reaver", "bully", "hashcat"],
                documentation="https://github.com/derv82/wifite2/wiki",
                github="https://github.com/derv82/wifite2",
                alternatives=["fern-wifi-cracker", "airgeddon", "fluxion"]
            ),
            
            "BETTERCAP": SecurityTool(
                name="Bettercap",
                category="Wireless",
                subcategory="Network Attack Framework",
                description="Swiss Army knife for WiFi, Bluetooth, and Ethernet networks",
                installation={
                    "linux": "apt-get install bettercap",
                    "go": "go get -u github.com/bettercap/bettercap"
                },
                usage=[
                    "bettercap -iface wlan0",
                    "bettercap -eval 'wifi.recon on; wifi.show'",
                    "bettercap -caplet http-ui"
                ],
                examples=[
                    {
                        "description": "Start with web UI",
                        "command": "bettercap -caplet http-ui"
                    },
                    {
                        "description": "WiFi reconnaissance",
                        "command": "bettercap -iface wlan0 -eval 'wifi.recon on; wifi.show'"
                    },
                    {
                        "description": "WiFi deauth attack",
                        "command": "bettercap -iface wlan0 -eval 'wifi.deauth AA:BB:CC:DD:EE:FF'"
                    },
                    {
                        "description": "ARP spoofing",
                        "command": "bettercap -iface eth0 -eval 'set arp.spoof.targets 192.168.1.100; arp.spoof on'"
                    },
                    {
                        "description": "Bluetooth scanning",
                        "command": "bettercap -eval 'ble.recon on; ble.show'"
                    }
                ],
                options=[
                    {"flag": "-iface", "description": "Network interface"},
                    {"flag": "-eval", "description": "Commands to execute"},
                    {"flag": "-caplet", "description": "Load caplet"},
                    {"flag": "-debug", "description": "Debug mode"},
                    {"flag": "-silent", "description": "Suppress events"}
                ],
                output_format="interactive",
                requires_root=True,
                api_support=True,
                gui_available=True,
                platform=["linux", "macos"],
                dependencies=["libpcap", "libnetfilter-queue"],
                documentation="https://www.bettercap.org/docs/",
                github="https://github.com/bettercap/bettercap",
                alternatives=["ettercap", "mitmproxy", "arpspoof"]
            ),
            
            "KISMET": SecurityTool(
                name="Kismet",
                category="Wireless",
                subcategory="Wireless Detector",
                description="Wireless network detector, sniffer, and intrusion detection system",
                installation={
                    "linux": "apt-get install kismet",
                    "source": "git clone https://github.com/kismetwireless/kismet.git"
                },
                usage=[
                    "kismet -c wlan0",
                    "kismet_client",
                    "kismet -c wlan0mon:name=wlan0mon"
                ],
                examples=[
                    {
                        "description": "Start Kismet server",
                        "command": "kismet -c wlan0"
                    },
                    {
                        "description": "Multiple interfaces",
                        "command": "kismet -c wlan0 -c wlan1"
                    },
                    {
                        "description": "Log to specific directory",
                        "command": "kismet -c wlan0 -t /path/to/logs/"
                    },
                    {
                        "description": "Web UI access",
                        "command": "Browse to http://localhost:2501"
                    },
                    {
                        "description": "GPS logging",
                        "command": "kismet -c wlan0 --use-gpsd-gps"
                    }
                ],
                options=[
                    {"flag": "-c", "description": "Capture source"},
                    {"flag": "-t", "description": "Log directory"},
                    {"flag": "--use-gpsd-gps", "description": "Use GPS"},
                    {"flag": "-n", "description": "No logging"},
                    {"flag": "--override", "description": "Override config"}
                ],
                output_format="pcap/kismet",
                requires_root=True,
                api_support=True,
                gui_available=True,
                platform=["linux"],
                dependencies=["libpcap", "wireless-tools"],
                documentation="https://www.kismetwireless.net/docs/",
                github="https://github.com/kismetwireless/kismet",
                alternatives=["airodump-ng", "wifi-explorer"]
            )
        }

class CloudSecurityTools:
    """Cloud Security Assessment Tools"""
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        return {
            "SCOUTSUITE": SecurityTool(
                name="ScoutSuite",
                category="Cloud Security",
                subcategory="Multi-cloud Security Auditing",
                description="Multi-cloud security auditing tool for AWS, Azure, GCP, Alibaba Cloud, and Oracle Cloud",
                installation={
                    "linux": "pip install scoutsuite",
                    "docker": "docker pull rossja/ncc-scoutsuite"
                },
                usage=[
                    "scout aws",
                    "scout azure --cli",
                    "scout gcp --project-id PROJECT_ID"
                ],
                examples=[
                    {
                        "description": "AWS audit",
                        "command": "scout aws --profile default"
                    },
                    {
                        "description": "Azure audit",
                        "command": "scout azure --cli --subscription-id SUB_ID"
                    },
                    {
                        "description": "GCP audit",
                        "command": "scout gcp --project-id my-project --key-file key.json"
                    },
                    {
                        "description": "Specific regions",
                        "command": "scout aws --regions us-east-1,eu-west-1"
                    },
                    {
                        "description": "HTML report",
                        "command": "scout aws --report-dir ./reports/"
                    }
                ],
                options=[
                    {"flag": "--profile", "description": "AWS profile"},
                    {"flag": "--regions", "description": "Specific regions"},
                    {"flag": "--report-dir", "description": "Report directory"},
                    {"flag": "--no-browser", "description": "Don't open browser"},
                    {"flag": "--force", "description": "Force overwrite"}
                ],
                output_format="html/json",
                requires_root=False,
                api_support=True,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["python3", "cloud SDKs"],
                documentation="https://github.com/nccgroup/ScoutSuite/wiki",
                github="https://github.com/nccgroup/ScoutSuite",
                alternatives=["Prowler", "CloudSploit", "CloudMapper"]
            ),
            
            "PROWLER": SecurityTool(
                name="Prowler",
                category="Cloud Security",
                subcategory="AWS Security Assessment",
                description="AWS security best practices assessment, auditing, hardening and forensics tool",
                installation={
                    "linux": "git clone https://github.com/prowler-cloud/prowler && cd prowler && pip install prowler-cloud",
                    "pip": "pip install prowler-cloud"
                },
                usage=[
                    "prowler",
                    "prowler -p custom-profile",
                    "prowler -c check_id"
                ],
                examples=[
                    {
                        "description": "Full AWS audit",
                        "command": "prowler aws"
                    },
                    {
                        "description": "Specific checks",
                        "command": "prowler aws -c iam_root_hardware_mfa_enabled"
                    },
                    {
                        "description": "CIS compliance",
                        "command": "prowler aws --compliance cis_2.0_aws"
                    },
                    {
                        "description": "Generate HTML report",
                        "command": "prowler aws -M html"
                    },
                    {
                        "description": "Check specific service",
                        "command": "prowler aws -s ec2"
                    }
                ],
                options=[
                    {"flag": "-p", "description": "AWS profile"},
                    {"flag": "-r", "description": "AWS region"},
                    {"flag": "-c", "description": "Specific check"},
                    {"flag": "-s", "description": "Service"},
                    {"flag": "-M", "description": "Output format"},
                    {"flag": "--compliance", "description": "Compliance framework"}
                ],
                output_format="html/json/csv",
                requires_root=False,
                api_support=True,
                gui_available=False,
                platform=["linux", "macos"],
                dependencies=["aws-cli", "python3"],
                documentation="https://docs.prowler.cloud/",
                github="https://github.com/prowler-cloud/prowler",
                alternatives=["ScoutSuite", "AWS Security Hub", "CloudCustodian"]
            ),
            
            "PACU": SecurityTool(
                name="Pacu",
                category="Cloud Security",
                subcategory="AWS Exploitation Framework",
                description="AWS exploitation framework for testing cloud security",
                installation={
                    "linux": "git clone https://github.com/RhinoSecurityLabs/pacu && cd pacu && bash install.sh"
                },
                usage=[
                    "python3 pacu.py",
                    "set_keys",
                    "run MODULE_NAME"
                ],
                examples=[
                    {
                        "description": "Start Pacu",
                        "command": "python3 pacu.py"
                    },
                    {
                        "description": "Set AWS keys",
                        "command": "Pacu > set_keys"
                    },
                    {
                        "description": "List modules",
                        "command": "Pacu > list"
                    },
                    {
                        "description": "Run enumeration",
                        "command": "Pacu > run iam__enum_permissions"
                    },
                    {
                        "description": "Privilege escalation",
                        "command": "Pacu > run iam__privesc_scan"
                    }
                ],
                options=[
                    {"flag": "set_keys", "description": "Configure AWS credentials"},
                    {"flag": "list", "description": "List modules"},
                    {"flag": "run", "description": "Execute module"},
                    {"flag": "data", "description": "View gathered data"},
                    {"flag": "services", "description": "List AWS services"}
                ],
                output_format="txt/json",
                requires_root=False,
                api_support=True,
                gui_available=False,
                platform=["linux", "macos"],
                dependencies=["python3", "boto3"],
                documentation="https://github.com/RhinoSecurityLabs/pacu/wiki",
                github="https://github.com/RhinoSecurityLabs/pacu",
                alternatives=["WeirdAAL", "aws-pwn", "Nimbostratus"]
            )
        }

class MobileSecurityTools:
    """Mobile Application Security Testing Tools"""
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        return {
            "MOBSF": SecurityTool(
                name="MobSF",
                category="Mobile Security",
                subcategory="Mobile Security Framework",
                description="Automated mobile application pentesting framework",
                installation={
                    "linux": "git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git && cd Mobile-Security-Framework-MobSF && ./setup.sh",
                    "docker": "docker pull opensecurity/mobile-security-framework-mobsf"
                },
                usage=[
                    "python3 manage.py runserver 0.0.0.0:8000",
                    "docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf"
                ],
                examples=[
                    {
                        "description": "Start MobSF",
                        "command": "python3 manage.py runserver 0.0.0.0:8000"
                    },
                    {
                        "description": "Docker deployment",
                        "command": "docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf"
                    },
                    {
                        "description": "Upload APK via API",
                        "command": "curl -F 'file=@app.apk' http://localhost:8000/api/v1/upload -H 'Authorization: API_KEY'"
                    },
                    {
                        "description": "Dynamic analysis",
                        "command": "Access http://localhost:8000 and use dynamic analyzer"
                    }
                ],
                options=[
                    {"flag": "runserver", "description": "Start server"},
                    {"flag": "-p", "description": "Port mapping"},
                    {"flag": "API_KEY", "description": "API authentication"},
                    {"flag": "upload", "description": "Upload application"}
                ],
                output_format="html/pdf/json",
                requires_root=False,
                api_support=True,
                gui_available=True,
                platform=["linux", "windows", "macos"],
                dependencies=["python3", "java", "android-sdk"],
                documentation="https://mobsf.github.io/docs/",
                github="https://github.com/MobSF/Mobile-Security-Framework-MobSF",
                alternatives=["QARK", "AndroBugs", "MARA"]
            ),
            
            "FRIDA": SecurityTool(
                name="Frida",
                category="Mobile Security",
                subcategory="Dynamic Instrumentation",
                description="Dynamic instrumentation toolkit for developers, reverse-engineers and security researchers",
                installation={
                    "linux": "pip install frida-tools",
                    "npm": "npm install frida"
                },
                usage=[
                    "frida -U com.example.app",
                    "frida-ps -U",
                    "frida-trace -U -i 'open*' com.example.app"
                ],
                examples=[
                    {
                        "description": "List processes",
                        "command": "frida-ps -U"
                    },
                    {
                        "description": "Attach to app",
                        "command": "frida -U com.example.app"
                    },
                    {
                        "description": "Trace API calls",
                        "command": "frida-trace -U -i 'recv*' -i 'send*' com.example.app"
                    },
                    {
                        "description": "Run script",
                        "command": "frida -U -l script.js com.example.app"
                    },
                    {
                        "description": "SSL pinning bypass",
                        "command": "frida -U -f com.example.app -l ssl-pinning-bypass.js --no-pause"
                    }
                ],
                options=[
                    {"flag": "-U", "description": "USB device"},
                    {"flag": "-f", "description": "Spawn process"},
                    {"flag": "-l", "description": "Load script"},
                    {"flag": "-i", "description": "Include pattern"},
                    {"flag": "--no-pause", "description": "Resume after spawn"}
                ],
                output_format="interactive",
                requires_root=False,
                api_support=True,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["python3", "node.js"],
                documentation="https://frida.re/docs/",
                github="https://github.com/frida/frida",
                alternatives=["Xposed", "Substrate", "ADBI"]
            ),
            
            "OBJECTION": SecurityTool(
                name="Objection",
                category="Mobile Security",
                subcategory="Runtime Exploration",
                description="Runtime mobile exploration toolkit powered by Frida",
                installation={
                    "linux": "pip3 install objection",
                    "pipx": "pipx install objection"
                },
                usage=[
                    "objection -g com.example.app explore",
                    "objection patchapk -s app.apk",
                    "objection -g com.example.app run command"
                ],
                examples=[
                    {
                        "description": "Explore app",
                        "command": "objection -g com.example.app explore"
                    },
                    {
                        "description": "Patch APK",
                        "command": "objection patchapk -s app.apk"
                    },
                    {
                        "description": "Disable SSL pinning",
                        "command": "android sslpinning disable"
                    },
                    {
                        "description": "Dump memory",
                        "command": "memory dump all /tmp/dump"
                    },
                    {
                        "description": "List activities",
                        "command": "android hooking list activities"
                    }
                ],
                options=[
                    {"flag": "-g", "description": "Gadget/package name"},
                    {"flag": "explore", "description": "Interactive mode"},
                    {"flag": "patchapk", "description": "Patch APK"},
                    {"flag": "run", "description": "Run command"},
                    {"flag": "-s", "description": "Source APK"}
                ],
                output_format="interactive",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["frida", "python3"],
                documentation="https://github.com/sensepost/objection/wiki",
                github="https://github.com/sensepost/objection",
                alternatives=["Frida CLI", "Cycript", "Needle"]
            )
        }