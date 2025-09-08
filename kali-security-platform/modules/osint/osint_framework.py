# OSINT Framework Module
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

@dataclass
class OSINTTool:
    """OSINT tool data model"""
    name: str
    category: str
    description: str
    use_cases: List[str] = field(default_factory=list)
    example_commands: List[str] = field(default_factory=list)
    api_required: bool = False
    documentation: str = ""

class OSINTFramework:
    """OSINT Framework manager"""
    
    def __init__(self):
        self.tools = []
        self.scenarios = {}
        self._initialize_tools()
        self._initialize_scenarios()
    
    def _initialize_tools(self):
        """Initialize OSINT tools"""
        
        self.tools = [
            OSINTTool(
                name="Shodan",
                category="Device Search",
                description="Search engine for Internet-connected devices",
                use_cases=["Find exposed databases", "Discover IoT devices", "SSL certificate search"],
                example_commands=["shodan search apache", "shodan host 8.8.8.8"],
                api_required=True
            ),
            OSINTTool(
                name="Censys",
                category="Internet Scanner",
                description="Internet-wide scanning and certificate database",
                use_cases=["Certificate transparency", "IPv4/IPv6 host discovery", "Service enumeration"],
                example_commands=["censys search 'parsed.names: example.com'"],
                api_required=True
            ),
            OSINTTool(
                name="theHarvester",
                category="Email Gathering",
                description="Email addresses and subdomain names harvester",
                use_cases=["Email enumeration", "Subdomain discovery", "Employee identification"],
                example_commands=["theHarvester -d example.com -b all"],
                api_required=False
            ),
            OSINTTool(
                name="Amass",
                category="Subdomain Enumeration",
                description="In-depth attack surface mapping",
                use_cases=["Subdomain enumeration", "ASN discovery", "DNS brute forcing"],
                example_commands=["amass enum -d example.com"],
                api_required=False
            ),
            OSINTTool(
                name="SpiderFoot",
                category="Automated OSINT",
                description="Automated OSINT collection",
                use_cases=["Automated reconnaissance", "Data correlation", "Report generation"],
                example_commands=["spiderfoot -s example.com"],
                api_required=False
            ),
            OSINTTool(
                name="Maltego",
                category="Data Visualization",
                description="Interactive data mining tool",
                use_cases=["Link analysis", "Data visualization", "Relationship mapping"],
                example_commands=["maltego"],
                api_required=False
            ),
            OSINTTool(
                name="Recon-ng",
                category="Web Reconnaissance",
                description="Full-featured reconnaissance framework",
                use_cases=["Modular reconnaissance", "API integration", "Report generation"],
                example_commands=["recon-ng", "marketplace install all"],
                api_required=False
            ),
            OSINTTool(
                name="Sherlock",
                category="Username OSINT",
                description="Username enumeration across social networks",
                use_cases=["Social media search", "Username availability", "Profile discovery"],
                example_commands=["sherlock username"],
                api_required=False
            ),
            OSINTTool(
                name="PhoneInfoga",
                category="Phone OSINT",
                description="Phone number information gathering",
                use_cases=["Phone number lookup", "Carrier identification", "Location tracking"],
                example_commands=["phoneinfoga scan -n +1234567890"],
                api_required=False
            ),
            OSINTTool(
                name="Metagoofil",
                category="Metadata Extraction",
                description="Metadata extractor from public documents",
                use_cases=["Metadata extraction", "Document discovery", "Information leakage"],
                example_commands=["metagoofil -d example.com -t pdf"],
                api_required=False
            ),
            OSINTTool(
                name="ExifTool",
                category="Metadata Analysis",
                description="Read and write meta information",
                use_cases=["EXIF data extraction", "GPS location discovery", "Camera identification"],
                example_commands=["exiftool image.jpg"],
                api_required=False
            ),
            OSINTTool(
                name="Google Dorks",
                category="Search Engine",
                description="Advanced Google search techniques",
                use_cases=["Sensitive file discovery", "Subdomain enumeration", "Information disclosure"],
                example_commands=["site:example.com filetype:pdf", "intitle:index.of"],
                api_required=False
            ),
            OSINTTool(
                name="Wayback Machine",
                category="Historical Data",
                description="Internet archive for historical website data",
                use_cases=["Historical analysis", "Deleted content recovery", "Change tracking"],
                example_commands=["waybackurls example.com"],
                api_required=False
            ),
            OSINTTool(
                name="DNSRecon",
                category="DNS Enumeration",
                description="DNS enumeration and scanning",
                use_cases=["DNS record enumeration", "Zone transfer", "Subdomain brute forcing"],
                example_commands=["dnsrecon -d example.com"],
                api_required=False
            ),
            OSINTTool(
                name="Subfinder",
                category="Subdomain Discovery",
                description="Fast passive subdomain enumeration",
                use_cases=["Passive subdomain discovery", "CI/CD integration", "Bug bounty"],
                example_commands=["subfinder -d example.com"],
                api_required=False
            ),
            OSINTTool(
                name="FOCA",
                category="Metadata Analysis",
                description="Fingerprinting Organizations with Collected Archives",
                use_cases=["Metadata analysis", "Network discovery", "User enumeration"],
                example_commands=["foca"],
                api_required=False
            ),
            OSINTTool(
                name="IntelX",
                category="Search Engine",
                description="Search engine for the deep and dark web",
                use_cases=["Leak detection", "Dark web monitoring", "Threat intelligence"],
                example_commands=["intelx.io search"],
                api_required=True
            )
        ]
    
    def _initialize_scenarios(self):
        """Initialize OSINT scenarios"""
        
        self.scenarios = {
            "company_reconnaissance": {
                "description": "Complete company reconnaissance workflow",
                "steps": [
                    {"tool": "Google Dorks", "action": "Search for exposed documents and pages"},
                    {"tool": "theHarvester", "action": "Gather email addresses and employee names"},
                    {"tool": "Amass", "action": "Enumerate subdomains"},
                    {"tool": "Shodan", "action": "Find exposed services and devices"},
                    {"tool": "Metagoofil", "action": "Extract metadata from documents"},
                    {"tool": "LinkedIn", "action": "Employee enumeration and role identification"}
                ]
            },
            "person_investigation": {
                "description": "Individual person investigation",
                "steps": [
                    {"tool": "Sherlock", "action": "Search username across platforms"},
                    {"tool": "Google", "action": "Search full name and variations"},
                    {"tool": "PhoneInfoga", "action": "Lookup phone number if available"},
                    {"tool": "Social Media", "action": "Manual search on social platforms"},
                    {"tool": "Have I Been Pwned", "action": "Check for data breaches"}
                ]
            },
            "domain_reconnaissance": {
                "description": "Domain and infrastructure mapping",
                "steps": [
                    {"tool": "DNSRecon", "action": "DNS enumeration"},
                    {"tool": "Subfinder", "action": "Passive subdomain discovery"},
                    {"tool": "Wayback Machine", "action": "Historical data analysis"},
                    {"tool": "Censys", "action": "Certificate transparency logs"},
                    {"tool": "BuiltWith", "action": "Technology stack identification"}
                ]
            },
            "threat_intelligence": {
                "description": "Threat intelligence gathering",
                "steps": [
                    {"tool": "VirusTotal", "action": "Check IPs and domains"},
                    {"tool": "AlienVault OTX", "action": "Threat intelligence feeds"},
                    {"tool": "IntelX", "action": "Search for leaked credentials"},
                    {"tool": "Shodan", "action": "Vulnerable service discovery"},
                    {"tool": "CVE Database", "action": "Vulnerability research"}
                ]
            }
        }
    
    def recommend_tools(self, objective: str) -> List[OSINTTool]:
        """Recommend tools based on objective"""
        objective_lower = objective.lower()
        recommendations = []
        
        keyword_map = {
            "email": ["theHarvester", "Hunter.io", "Recon-ng"],
            "subdomain": ["Amass", "Subfinder", "DNSRecon"],
            "person": ["Sherlock", "PhoneInfoga", "Social Media"],
            "company": ["theHarvester", "Shodan", "Metagoofil"],
            "phone": ["PhoneInfoga", "TrueCaller"],
            "metadata": ["Metagoofil", "ExifTool", "FOCA"],
            "social": ["Sherlock", "Social Media", "Maltego"],
            "dns": ["DNSRecon", "Amass", "dnstwist"],
            "leak": ["Have I Been Pwned", "IntelX", "Dehashed"]
        }
        
        for keyword, tool_names in keyword_map.items():
            if keyword in objective_lower:
                for tool_name in tool_names:
                    tool = self.get_tool_by_name(tool_name)
                    if tool and tool not in recommendations:
                        recommendations.append(tool)
        
        return recommendations[:5]  # Return top 5 recommendations
    
    def get_tool_by_name(self, name: str) -> Optional[OSINTTool]:
        """Get tool by name"""
        for tool in self.tools:
            if tool.name.lower() == name.lower():
                return tool
        return None
    
    def get_tools_by_category(self, category: str) -> List[OSINTTool]:
        """Get tools by category"""
        return [tool for tool in self.tools if tool.category.lower() == category.lower()]
    
    def generate_recon_plan(self, target_type: str, target: str) -> Dict[str, Any]:
        """Generate reconnaissance plan"""
        
        plans = {
            "domain": {
                "target": target,
                "type": "Domain Reconnaissance",
                "phases": [
                    {
                        "phase": "Passive Reconnaissance",
                        "tools": ["Google Dorks", "Wayback Machine", "DNSRecon"],
                        "duration": "1-2 hours"
                    },
                    {
                        "phase": "Subdomain Enumeration",
                        "tools": ["Amass", "Subfinder", "DNSRecon"],
                        "duration": "2-4 hours"
                    },
                    {
                        "phase": "Service Discovery",
                        "tools": ["Shodan", "Censys", "Nmap"],
                        "duration": "1-2 hours"
                    },
                    {
                        "phase": "Information Gathering",
                        "tools": ["theHarvester", "Metagoofil", "ExifTool"],
                        "duration": "2-3 hours"
                    }
                ]
            },
            "company": {
                "target": target,
                "type": "Company Reconnaissance",
                "phases": [
                    {
                        "phase": "Public Information",
                        "tools": ["Google", "LinkedIn", "Company Website"],
                        "duration": "1 hour"
                    },
                    {
                        "phase": "Employee Enumeration",
                        "tools": ["theHarvester", "LinkedIn", "Hunter.io"],
                        "duration": "2-3 hours"
                    },
                    {
                        "phase": "Technical Infrastructure",
                        "tools": ["Shodan", "Censys", "BuiltWith"],
                        "duration": "2-3 hours"
                    },
                    {
                        "phase": "Document Analysis",
                        "tools": ["Metagoofil", "FOCA", "Google Dorks"],
                        "duration": "2-3 hours"
                    }
                ]
            },
            "person": {
                "target": target,
                "type": "Person Investigation",
                "phases": [
                    {
                        "phase": "Username Search",
                        "tools": ["Sherlock", "WhatsMyName", "NameCheckr"],
                        "duration": "30 minutes"
                    },
                    {
                        "phase": "Social Media",
                        "tools": ["Social Media Platforms", "Google", "Yandex"],
                        "duration": "1-2 hours"
                    },
                    {
                        "phase": "Data Breach Check",
                        "tools": ["Have I Been Pwned", "Dehashed", "IntelX"],
                        "duration": "30 minutes"
                    },
                    {
                        "phase": "Additional Information",
                        "tools": ["PhoneInfoga", "Email Finder", "Public Records"],
                        "duration": "1-2 hours"
                    }
                ]
            }
        }
        
        return plans.get(target_type, {
            "target": target,
            "type": "Generic Reconnaissance",
            "phases": [{"phase": "Information Gathering", "tools": ["Google", "Shodan"], "duration": "2-3 hours"}]
        })

# Create default instance
osint_framework = OSINTFramework()
