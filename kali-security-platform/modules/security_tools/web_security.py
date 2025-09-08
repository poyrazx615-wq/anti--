#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Complete Security Tools Integration Module - Part 1
Web Scanners, Fuzzers, and Web Exploitation Tools
"""

from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import subprocess
import asyncio
import json

@dataclass
class SecurityTool:
    """Security tool information structure"""
    name: str
    category: str
    subcategory: str
    description: str
    installation: Dict[str, str]  # OS-specific installation commands
    usage: List[str]
    examples: List[Dict[str, str]]
    options: List[Dict[str, str]]
    output_format: str
    requires_root: bool
    api_support: bool
    gui_available: bool
    platform: List[str]  # linux, windows, macos
    dependencies: List[str]
    documentation: str
    github: str
    alternatives: List[str]

class WebSecurityTools:
    """Web Application Security Tools"""
    
    def __init__(self):
        self.tools = self._initialize_tools()
    
    def _initialize_tools(self) -> Dict[str, SecurityTool]:
        return {
            # ===== WEB VULNERABILITY SCANNERS =====
            "NUCLEI": SecurityTool(
                name="Nuclei",
                category="Web Scanner",
                subcategory="Template-based Scanner",
                description="Fast and customizable vulnerability scanner based on templates",
                installation={
                    "linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                    "windows": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                    "docker": "docker pull projectdiscovery/nuclei:latest"
                },
                usage=[
                    "nuclei -u https://target.com",
                    "nuclei -l urls.txt",
                    "nuclei -u https://target.com -t cves/",
                    "nuclei -u https://target.com -severity critical,high"
                ],
                examples=[
                    {
                        "description": "Scan single target with all templates",
                        "command": "nuclei -u https://example.com -v"
                    },
                    {
                        "description": "Scan with specific severity",
                        "command": "nuclei -u https://example.com -severity critical,high -o results.txt"
                    },
                    {
                        "description": "Scan multiple targets from file",
                        "command": "nuclei -l targets.txt -t cves/ -c 50"
                    },
                    {
                        "description": "Custom template scan",
                        "command": "nuclei -u https://example.com -t custom-templates/ -v"
                    },
                    {
                        "description": "Rate limited scan",
                        "command": "nuclei -u https://example.com -rl 150 -c 30"
                    }
                ],
                options=[
                    {"flag": "-u", "description": "Target URL"},
                    {"flag": "-l", "description": "List of URLs"},
                    {"flag": "-t", "description": "Templates to run"},
                    {"flag": "-severity", "description": "Filter by severity"},
                    {"flag": "-o", "description": "Output file"},
                    {"flag": "-json", "description": "JSON output"},
                    {"flag": "-rl", "description": "Rate limit"},
                    {"flag": "-c", "description": "Concurrency"}
                ],
                output_format="txt/json/yaml",
                requires_root=False,
                api_support=True,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["go"],
                documentation="https://nuclei.projectdiscovery.io",
                github="https://github.com/projectdiscovery/nuclei",
                alternatives=["OWASP ZAP", "Burp Suite", "Nikto"]
            ),
            
            "ZAP": SecurityTool(
                name="OWASP ZAP",
                category="Web Scanner",
                subcategory="Web Application Scanner",
                description="OWASP Zed Attack Proxy - Comprehensive web app security scanner",
                installation={
                    "linux": "sudo snap install zaproxy --classic",
                    "windows": "choco install zap",
                    "docker": "docker pull owasp/zap2docker-stable"
                },
                usage=[
                    "zap.sh -daemon -port 8080",
                    "zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' http://target.com",
                    "zap.py -t http://target.com -g gen.conf -r report.html"
                ],
                examples=[
                    {
                        "description": "Quick scan",
                        "command": "zap-cli quick-scan --self-contained http://example.com"
                    },
                    {
                        "description": "Full scan with report",
                        "command": "zap-cli start && zap-cli spider http://example.com && zap-cli active-scan http://example.com && zap-cli report -o report.html -f html"
                    },
                    {
                        "description": "API scan",
                        "command": "zap-cli openapi http://example.com/api/swagger.json"
                    },
                    {
                        "description": "Authenticated scan",
                        "command": "zap-cli --zap-url http://127.0.0.1 -p 8080 context import context.xml"
                    }
                ],
                options=[
                    {"flag": "-daemon", "description": "Run in daemon mode"},
                    {"flag": "-port", "description": "Port to listen on"},
                    {"flag": "-config", "description": "Configuration options"},
                    {"flag": "spider", "description": "Spider the target"},
                    {"flag": "active-scan", "description": "Active scanning"},
                    {"flag": "report", "description": "Generate report"}
                ],
                output_format="html/xml/json/md",
                requires_root=False,
                api_support=True,
                gui_available=True,
                platform=["linux", "windows", "macos"],
                dependencies=["java"],
                documentation="https://www.zaproxy.org/docs/",
                github="https://github.com/zaproxy/zaproxy",
                alternatives=["Burp Suite", "Acunetix", "Nikto"]
            ),
            
            # ===== WEB FUZZING TOOLS =====
            "FFUF": SecurityTool(
                name="FFuF",
                category="Fuzzer",
                subcategory="Web Fuzzer",
                description="Fast web fuzzer written in Go",
                installation={
                    "linux": "go install github.com/ffuf/ffuf@latest",
                    "windows": "go install github.com/ffuf/ffuf@latest",
                    "apt": "sudo apt install ffuf"
                },
                usage=[
                    "ffuf -w wordlist.txt -u https://target.com/FUZZ",
                    "ffuf -w wordlist.txt -u https://target.com -H 'Host: FUZZ.target.com'",
                    "ffuf -w users.txt:USER -w passwords.txt:PASS -u https://target.com/login -X POST -d 'username=USER&password=PASS'"
                ],
                examples=[
                    {
                        "description": "Directory fuzzing",
                        "command": "ffuf -w /usr/share/wordlists/dirb/common.txt -u https://example.com/FUZZ"
                    },
                    {
                        "description": "Subdomain fuzzing",
                        "command": "ffuf -w subdomains.txt -H 'Host: FUZZ.example.com' -u https://example.com"
                    },
                    {
                        "description": "Parameter fuzzing",
                        "command": "ffuf -w params.txt -u https://example.com/search?FUZZ=test"
                    },
                    {
                        "description": "POST data fuzzing",
                        "command": "ffuf -w wordlist.txt -X POST -d 'username=admin&password=FUZZ' -u https://example.com/login"
                    },
                    {
                        "description": "Header fuzzing",
                        "command": "ffuf -w headers.txt -u https://example.com -H 'FUZZ: value'"
                    },
                    {
                        "description": "Extension fuzzing",
                        "command": "ffuf -w wordlist.txt -u https://example.com/indexFUZZ -e .php,.html,.txt"
                    }
                ],
                options=[
                    {"flag": "-w", "description": "Wordlist"},
                    {"flag": "-u", "description": "Target URL"},
                    {"flag": "-H", "description": "Header"},
                    {"flag": "-X", "description": "HTTP method"},
                    {"flag": "-d", "description": "POST data"},
                    {"flag": "-mc", "description": "Match status codes"},
                    {"flag": "-fc", "description": "Filter status codes"},
                    {"flag": "-fs", "description": "Filter by size"},
                    {"flag": "-fw", "description": "Filter by word count"},
                    {"flag": "-t", "description": "Threads"},
                    {"flag": "-rate", "description": "Rate limit"}
                ],
                output_format="json/csv/html",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["go"],
                documentation="https://github.com/ffuf/ffuf/wiki",
                github="https://github.com/ffuf/ffuf",
                alternatives=["wfuzz", "gobuster", "dirsearch"]
            ),
            
            "WFUZZ": SecurityTool(
                name="Wfuzz",
                category="Fuzzer",
                subcategory="Web Application Fuzzer",
                description="Web application fuzzer for brute forcing web applications",
                installation={
                    "linux": "pip install wfuzz",
                    "windows": "pip install wfuzz",
                    "apt": "sudo apt install wfuzz"
                },
                usage=[
                    "wfuzz -c -z file,wordlist.txt https://target.com/FUZZ",
                    "wfuzz -c -z file,users.txt -z file,pass.txt --sc 200 https://target.com/login.php?user=FUZZ&pass=FUZ2Z",
                    "wfuzz -c -w wordlist.txt --hc 404 https://target.com/FUZZ"
                ],
                examples=[
                    {
                        "description": "Basic directory fuzzing",
                        "command": "wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 https://example.com/FUZZ"
                    },
                    {
                        "description": "POST request fuzzing",
                        "command": "wfuzz -c -z file,passwords.txt -d 'username=admin&password=FUZZ' https://example.com/login"
                    },
                    {
                        "description": "Cookie fuzzing",
                        "command": "wfuzz -c -z file,values.txt -H 'Cookie: session=FUZZ' https://example.com/admin"
                    },
                    {
                        "description": "Multiple parameter fuzzing",
                        "command": "wfuzz -c -z file,users.txt -z file,passwords.txt https://example.com/login?user=FUZZ&pass=FUZ2Z"
                    }
                ],
                options=[
                    {"flag": "-c", "description": "Color output"},
                    {"flag": "-z", "description": "Payload type"},
                    {"flag": "--hc", "description": "Hide status codes"},
                    {"flag": "--sc", "description": "Show status codes"},
                    {"flag": "-t", "description": "Threads"},
                    {"flag": "-d", "description": "POST data"},
                    {"flag": "-H", "description": "Headers"}
                ],
                output_format="json/csv/html",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["python", "pycurl"],
                documentation="https://wfuzz.readthedocs.io",
                github="https://github.com/xmendez/wfuzz",
                alternatives=["ffuf", "gobuster", "dirbuster"]
            ),
            
            "GOBUSTER": SecurityTool(
                name="Gobuster",
                category="Fuzzer",
                subcategory="Directory/File/DNS Fuzzer",
                description="Fast directory, file, DNS and VHost busting tool",
                installation={
                    "linux": "go install github.com/OJ/gobuster/v3@latest",
                    "windows": "go install github.com/OJ/gobuster/v3@latest",
                    "apt": "sudo apt install gobuster"
                },
                usage=[
                    "gobuster dir -u https://target.com -w wordlist.txt",
                    "gobuster dns -d target.com -w subdomains.txt",
                    "gobuster vhost -u https://target.com -w vhosts.txt"
                ],
                examples=[
                    {
                        "description": "Directory busting",
                        "command": "gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt"
                    },
                    {
                        "description": "DNS subdomain busting",
                        "command": "gobuster dns -d example.com -w /usr/share/wordlists/subdomains.txt"
                    },
                    {
                        "description": "VHost discovery",
                        "command": "gobuster vhost -u https://example.com -w /usr/share/wordlists/vhosts.txt"
                    },
                    {
                        "description": "With authentication",
                        "command": "gobuster dir -u https://example.com -w wordlist.txt -U admin -P password"
                    }
                ],
                options=[
                    {"flag": "dir", "description": "Directory/file mode"},
                    {"flag": "dns", "description": "DNS mode"},
                    {"flag": "vhost", "description": "VHost mode"},
                    {"flag": "-u", "description": "Target URL"},
                    {"flag": "-w", "description": "Wordlist"},
                    {"flag": "-x", "description": "Extensions"},
                    {"flag": "-t", "description": "Threads"},
                    {"flag": "-k", "description": "Skip SSL verification"}
                ],
                output_format="txt/json",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["go"],
                documentation="https://github.com/OJ/gobuster",
                github="https://github.com/OJ/gobuster",
                alternatives=["ffuf", "wfuzz", "dirsearch"]
            ),
            
            # ===== WEB EXPLOITATION TOOLS =====
            "COMMIX": SecurityTool(
                name="Commix",
                category="Exploitation",
                subcategory="Command Injection",
                description="Automated command injection exploitation tool",
                installation={
                    "linux": "git clone https://github.com/commixproject/commix.git",
                    "windows": "git clone https://github.com/commixproject/commix.git",
                    "pip": "pip install commix"
                },
                usage=[
                    "python commix.py -u 'http://target.com/page.php?id=1'",
                    "python commix.py -u 'http://target.com/' --data='param=value'",
                    "python commix.py -r request.txt"
                ],
                examples=[
                    {
                        "description": "GET parameter testing",
                        "command": "python commix.py -u 'http://example.com/page.php?id=1'"
                    },
                    {
                        "description": "POST parameter testing",
                        "command": "python commix.py -u 'http://example.com/form.php' --data='name=test&comment=hello'"
                    },
                    {
                        "description": "Cookie injection",
                        "command": "python commix.py -u 'http://example.com/' --cookie='session=test'"
                    },
                    {
                        "description": "User-Agent injection",
                        "command": "python commix.py -u 'http://example.com/' --user-agent='Commix'"
                    },
                    {
                        "description": "From Burp request",
                        "command": "python commix.py -r request.txt --force-ssl"
                    }
                ],
                options=[
                    {"flag": "-u", "description": "Target URL"},
                    {"flag": "--data", "description": "POST data"},
                    {"flag": "-r", "description": "Load HTTP request from file"},
                    {"flag": "--cookie", "description": "HTTP Cookie header"},
                    {"flag": "--user-agent", "description": "HTTP User-Agent header"},
                    {"flag": "--os-shell", "description": "Spawn an OS shell"},
                    {"flag": "--batch", "description": "Never ask for user input"}
                ],
                output_format="txt",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["python"],
                documentation="https://github.com/commixproject/commix/wiki",
                github="https://github.com/commixproject/commix",
                alternatives=["manual testing", "custom scripts"]
            ),
            
            "XSSTRIKE": SecurityTool(
                name="XSStrike",
                category="Exploitation",
                subcategory="XSS Scanner",
                description="Advanced XSS detection and exploitation suite",
                installation={
                    "linux": "git clone https://github.com/s0md3v/XSStrike.git && cd XSStrike && pip install -r requirements.txt",
                    "windows": "git clone https://github.com/s0md3v/XSStrike.git && cd XSStrike && pip install -r requirements.txt"
                },
                usage=[
                    "python xsstrike.py -u 'http://target.com/page.php?q=query'",
                    "python xsstrike.py -u 'http://target.com/search' --data 'q=query'",
                    "python xsstrike.py -u 'http://target.com' --crawl"
                ],
                examples=[
                    {
                        "description": "Single URL scan",
                        "command": "python xsstrike.py -u 'http://example.com/search.php?q=test'"
                    },
                    {
                        "description": "POST request scan",
                        "command": "python xsstrike.py -u 'http://example.com/form.php' --data 'name=test&email=test@test.com'"
                    },
                    {
                        "description": "Crawl and scan",
                        "command": "python xsstrike.py -u 'http://example.com' --crawl -l 3"
                    },
                    {
                        "description": "Blind XSS testing",
                        "command": "python xsstrike.py -u 'http://example.com/contact' --blind"
                    },
                    {
                        "description": "Custom payload",
                        "command": "python xsstrike.py -u 'http://example.com/search?q=FUZZ' --file payloads.txt"
                    }
                ],
                options=[
                    {"flag": "-u", "description": "Target URL"},
                    {"flag": "--data", "description": "POST data"},
                    {"flag": "--crawl", "description": "Crawl the website"},
                    {"flag": "-l", "description": "Crawl depth"},
                    {"flag": "--blind", "description": "Blind XSS testing"},
                    {"flag": "--fuzzer", "description": "Fuzzer mode"},
                    {"flag": "--timeout", "description": "Timeout"}
                ],
                output_format="txt/json",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["python", "mechanize", "beautifulsoup4"],
                documentation="https://github.com/s0md3v/XSStrike/wiki",
                github="https://github.com/s0md3v/XSStrike",
                alternatives=["dalfox", "xsser", "xenotix"]
            ),
            
            "NOSQLMAP": SecurityTool(
                name="NoSQLMap",
                category="Exploitation",
                subcategory="NoSQL Injection",
                description="NoSQL injection and database takeover tool",
                installation={
                    "linux": "git clone https://github.com/codingo/NoSQLMap.git && cd NoSQLMap && python setup.py install",
                    "windows": "git clone https://github.com/codingo/NoSQLMap.git && cd NoSQLMap && python setup.py install"
                },
                usage=[
                    "python nosqlmap.py",
                    "python nosqlmap.py -u http://target.com -p username",
                    "python nosqlmap.py -r request.txt"
                ],
                examples=[
                    {
                        "description": "Interactive mode",
                        "command": "python nosqlmap.py"
                    },
                    {
                        "description": "Test specific parameter",
                        "command": "python nosqlmap.py -u http://example.com/login -p username"
                    },
                    {
                        "description": "From request file",
                        "command": "python nosqlmap.py -r login_request.txt"
                    },
                    {
                        "description": "MongoDB specific",
                        "command": "python nosqlmap.py -u http://example.com/api -p search --dbms mongodb"
                    }
                ],
                options=[
                    {"flag": "-u", "description": "Target URL"},
                    {"flag": "-p", "description": "Parameter to test"},
                    {"flag": "-r", "description": "Request file"},
                    {"flag": "--dbms", "description": "Database type"},
                    {"flag": "--technique", "description": "Injection technique"}
                ],
                output_format="txt",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "windows", "macos"],
                dependencies=["python", "pymongo", "couchdb"],
                documentation="https://github.com/codingo/NoSQLMap",
                github="https://github.com/codingo/NoSQLMap",
                alternatives=["NoSQLi Scanner", "manual testing"]
            ),
            
            "GITTOOLS": SecurityTool(
                name="GitTools",
                category="Exploitation",
                subcategory="Git Exploitation",
                description="Tools for exploiting exposed .git repositories",
                installation={
                    "linux": "git clone https://github.com/internetwache/GitTools.git",
                    "windows": "git clone https://github.com/internetwache/GitTools.git"
                },
                usage=[
                    "./gitdumper.sh https://target.com/.git/ output_dir",
                    "./extractor.sh output_dir extracted_dir",
                    "./gitfinder.py -i urls.txt"
                ],
                examples=[
                    {
                        "description": "Dump exposed .git",
                        "command": "./gitdumper.sh https://example.com/.git/ dumped"
                    },
                    {
                        "description": "Extract repository",
                        "command": "./extractor.sh dumped extracted"
                    },
                    {
                        "description": "Find .git exposures",
                        "command": "./gitfinder.py -i domains.txt -o found_git.txt"
                    },
                    {
                        "description": "Complete workflow",
                        "command": "./gitdumper.sh https://example.com/.git/ dump && ./extractor.sh dump extract && cd extract && git log"
                    }
                ],
                options=[
                    {"flag": "-i", "description": "Input file"},
                    {"flag": "-o", "description": "Output directory"},
                    {"flag": "-t", "description": "Threads"},
                    {"flag": "-v", "description": "Verbose output"}
                ],
                output_format="directory",
                requires_root=False,
                api_support=False,
                gui_available=False,
                platform=["linux", "macos"],
                dependencies=["bash", "git", "python"],
                documentation="https://github.com/internetwache/GitTools",
                github="https://github.com/internetwache/GitTools",
                alternatives=["git-dumper", "dvcs-ripper"]
            )
        }
    
    def get_tool(self, tool_name: str) -> Optional[SecurityTool]:
        """Get specific tool information"""
        return self.tools.get(tool_name.upper())
    
    def get_tools_by_category(self, category: str) -> List[SecurityTool]:
        """Get tools by category"""
        return [tool for tool in self.tools.values() if tool.category.lower() == category.lower()]
    
    def get_tools_by_subcategory(self, subcategory: str) -> List[SecurityTool]:
        """Get tools by subcategory"""
        return [tool for tool in self.tools.values() if tool.subcategory.lower() == subcategory.lower()]
    
    def search_tools(self, keyword: str) -> List[SecurityTool]:
        """Search tools by keyword"""
        keyword_lower = keyword.lower()
        results = []
        for tool in self.tools.values():
            if (keyword_lower in tool.name.lower() or
                keyword_lower in tool.description.lower() or
                keyword_lower in tool.category.lower() or
                keyword_lower in tool.subcategory.lower()):
                results.append(tool)
        return results