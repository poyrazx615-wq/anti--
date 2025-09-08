# Security Tools Manager Module
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import json
from pathlib import Path

@dataclass
class SecurityTool:
    """Security tool data model"""
    name: str
    category: str
    subcategory: str = ""
    description: str = ""
    installation: Dict = field(default_factory=dict)
    usage: str = ""
    examples: List[Dict] = field(default_factory=list)
    options: List[Dict] = field(default_factory=list)
    output_format: str = "text"
    requires_root: bool = False
    gui_available: bool = False
    api_support: bool = False
    platform: List[str] = field(default_factory=lambda: ["linux"])
    dependencies: List[str] = field(default_factory=list)
    documentation: str = ""
    github: str = ""
    alternatives: List[str] = field(default_factory=list)

class SecurityToolsManager:
    """Manager for all security tools"""
    
    def __init__(self):
        self.all_tools = {}
        self.categories = {}
        self._load_all_tools()
    
    def _load_all_tools(self):
        """Load all security tools definitions"""
        
        # Web Security Tools
        self.all_tools["nmap"] = SecurityTool(
            name="Nmap",
            category="Network Scanner",
            description="Network exploration and security auditing",
            installation={"apt": "apt install nmap", "pip": ""},
            usage="nmap [options] [target]",
            examples=[
                {"description": "Basic scan", "command": "nmap 192.168.1.1"},
                {"description": "Service version detection", "command": "nmap -sV target.com"},
                {"description": "OS detection", "command": "nmap -O target.com"},
                {"description": "Aggressive scan", "command": "nmap -A target.com"}
            ],
            options=[
                {"flag": "-sS", "description": "TCP SYN scan"},
                {"flag": "-sV", "description": "Service version detection"},
                {"flag": "-O", "description": "OS detection"},
                {"flag": "-A", "description": "Aggressive scan"},
                {"flag": "-p", "description": "Port specification"}
            ],
            requires_root=True,
            gui_available=True,
            api_support=True,
            alternatives=["masscan", "zmap", "unicornscan"]
        )
        
        self.all_tools["sqlmap"] = SecurityTool(
            name="SQLMap",
            category="Web Scanner",
            subcategory="SQL Injection",
            description="Automatic SQL injection and database takeover tool",
            installation={"apt": "apt install sqlmap", "pip": "pip install sqlmap"},
            usage="sqlmap -u URL [options]",
            examples=[
                {"description": "Test URL for SQL injection", "command": "sqlmap -u 'http://target.com/page.php?id=1'"},
                {"description": "Enumerate databases", "command": "sqlmap -u URL --dbs"},
                {"description": "Dump database", "command": "sqlmap -u URL -D dbname --dump"}
            ],
            options=[
                {"flag": "--dbs", "description": "Enumerate databases"},
                {"flag": "--tables", "description": "Enumerate tables"},
                {"flag": "--dump", "description": "Dump data"},
                {"flag": "--batch", "description": "Never ask for user input"}
            ],
            api_support=True
        )
        
        self.all_tools["metasploit"] = SecurityTool(
            name="Metasploit",
            category="Exploitation",
            description="Penetration testing framework",
            installation={"apt": "apt install metasploit-framework"},
            usage="msfconsole",
            examples=[
                {"description": "Start console", "command": "msfconsole"},
                {"description": "Search exploits", "command": "search type:exploit platform:windows"},
                {"description": "Use exploit", "command": "use exploit/windows/smb/ms17_010_eternalblue"}
            ],
            requires_root=True,
            gui_available=True
        )
        
        self.all_tools["burpsuite"] = SecurityTool(
            name="Burp Suite",
            category="Web Scanner",
            description="Web vulnerability scanner and proxy",
            installation={"manual": "Download from portswigger.net"},
            gui_available=True,
            api_support=True
        )
        
        self.all_tools["hydra"] = SecurityTool(
            name="Hydra",
            category="Password Cracking",
            description="Fast and flexible online password cracking tool",
            installation={"apt": "apt install hydra"},
            usage="hydra [options] target",
            examples=[
                {"description": "SSH brute force", "command": "hydra -l admin -P passwords.txt ssh://192.168.1.1"},
                {"description": "FTP brute force", "command": "hydra -L users.txt -P pass.txt ftp://target.com"}
            ]
        )
        
        self.all_tools["nikto"] = SecurityTool(
            name="Nikto",
            category="Web Scanner",
            description="Web server scanner",
            installation={"apt": "apt install nikto"},
            usage="nikto -h target",
            examples=[
                {"description": "Basic scan", "command": "nikto -h http://target.com"},
                {"description": "Scan with SSL", "command": "nikto -h https://target.com -ssl"}
            ]
        )
        
        # Add more tools...
        self._organize_by_category()
    
    def _organize_by_category(self):
        """Organize tools by category"""
        for tool_name, tool in self.all_tools.items():
            if tool.category not in self.categories:
                self.categories[tool.category] = []
            self.categories[tool.category].append(tool_name)
    
    def get_tool(self, name: str) -> Optional[SecurityTool]:
        """Get tool by name"""
        # Case insensitive search
        for key, tool in self.all_tools.items():
            if key.lower() == name.lower():
                return tool
        return None
    
    def get_tools_by_category(self, category: str) -> List[SecurityTool]:
        """Get all tools in a category"""
        tools = []
        for tool_name in self.categories.get(category, []):
            tool = self.all_tools.get(tool_name)
            if tool:
                tools.append(tool)
        return tools
    
    def search_tools(self, query: str) -> List[SecurityTool]:
        """Search tools by name or description"""
        results = []
        query_lower = query.lower()
        
        for tool in self.all_tools.values():
            if (query_lower in tool.name.lower() or 
                query_lower in tool.description.lower() or
                query_lower in tool.category.lower()):
                results.append(tool)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get platform statistics"""
        stats = {
            "total_tools": len(self.all_tools),
            "categories": {},
            "has_gui": 0,
            "has_api": 0,
            "requires_root": 0
        }
        
        for category, tools in self.categories.items():
            stats["categories"][category] = len(tools)
        
        for tool in self.all_tools.values():
            if tool.gui_available:
                stats["has_gui"] += 1
            if tool.api_support:
                stats["has_api"] += 1
            if tool.requires_root:
                stats["requires_root"] += 1
        
        return stats
    
    def create_pentest_workflow(self, target_type: str) -> Dict[str, List[str]]:
        """Create penetration testing workflow"""
        workflows = {
            "web_application": {
                "1_reconnaissance": ["nmap", "nikto", "dirb"],
                "2_scanning": ["burpsuite", "sqlmap", "xsstrike"],
                "3_exploitation": ["metasploit", "commix"],
                "4_post_exploitation": ["weevely", "empire"]
            },
            "network": {
                "1_discovery": ["nmap", "masscan", "arp-scan"],
                "2_enumeration": ["enum4linux", "smbclient", "rpcclient"],
                "3_vulnerability_assessment": ["nessus", "openvas"],
                "4_exploitation": ["metasploit", "crackmapexec"],
                "5_lateral_movement": ["psexec", "wmiexec", "evil-winrm"]
            },
            "active_directory": {
                "1_enumeration": ["bloodhound", "powerview", "adrecon"],
                "2_kerberos_attacks": ["rubeus", "impacket", "kerbrute"],
                "3_credential_harvesting": ["mimikatz", "lazagne", "secretsdump"],
                "4_persistence": ["empire", "covenant", "powersploit"]
            },
            "wireless": {
                "1_monitoring": ["airmon-ng", "kismet"],
                "2_capture": ["airodump-ng", "wireshark"],
                "3_cracking": ["aircrack-ng", "hashcat", "john"],
                "4_evil_twin": ["hostapd", "dnsmasq", "bettercap"]
            },
            "mobile": {
                "1_static_analysis": ["mobsf", "apktool", "jadx"],
                "2_dynamic_analysis": ["frida", "objection", "drozer"],
                "3_network_analysis": ["burpsuite", "wireshark", "tcpdump"]
            },
            "cloud": {
                "1_enumeration": ["scoutsuite", "prowler", "cloudsploit"],
                "2_exploitation": ["pacu", "nimbostratus", "cloudgoat"],
                "3_persistence": ["aws-cli", "azure-cli", "gcloud"]
            }
        }
        
        return workflows.get(target_type, {})

# Create default instance
tools_manager = SecurityToolsManager()
