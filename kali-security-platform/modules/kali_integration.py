# Kali Linux Tools Integration Module
import os
import subprocess
import asyncio
import json
import shutil
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import xml.etree.ElementTree as ET
import re
from datetime import datetime

class KaliToolsManager:
    """Manager for Kali Linux tools integration"""
    
    def __init__(self):
        self.tools_config = self._load_tools_config()
        self.available_tools = {}
        
    def _load_tools_config(self) -> Dict:
        """Load Kali tools configuration"""
        return {
            'nmap': {
                'command': 'nmap',
                'description': 'Network exploration and security auditing',
                'category': 'network',
                'wrapper': NmapWrapper
            },
            'masscan': {
                'command': 'masscan',
                'description': 'Fast port scanner',
                'category': 'network',
                'wrapper': MasscanWrapper
            },
            'nikto': {
                'command': 'nikto',
                'description': 'Web server scanner',
                'category': 'web',
                'wrapper': NiktoWrapper
            },
            'sqlmap': {
                'command': 'sqlmap',
                'description': 'SQL injection tool',
                'category': 'web',
                'wrapper': SqlmapWrapper
            },
            'metasploit': {
                'command': 'msfconsole',
                'description': 'Penetration testing framework',
                'category': 'exploitation',
                'wrapper': MetasploitWrapper
            },
            'hydra': {
                'command': 'hydra',
                'description': 'Password cracking tool',
                'category': 'password',
                'wrapper': HydraWrapper
            },
            'john': {
                'command': 'john',
                'description': 'John the Ripper password cracker',
                'category': 'password',
                'wrapper': JohnWrapper
            },
            'aircrack-ng': {
                'command': 'aircrack-ng',
                'description': 'WiFi security auditing',
                'category': 'wireless',
                'wrapper': AircrackWrapper
            },
            'gobuster': {
                'command': 'gobuster',
                'description': 'Directory/file & DNS busting tool',
                'category': 'web',
                'wrapper': GobusterWrapper
            },
            'wpscan': {
                'command': 'wpscan',
                'description': 'WordPress vulnerability scanner',
                'category': 'web',
                'wrapper': WpscanWrapper
            },
            'burpsuite': {
                'command': 'burpsuite',
                'description': 'Web application security testing',
                'category': 'web',
                'wrapper': BurpsuiteWrapper
            },
            'theharvester': {
                'command': 'theHarvester',
                'description': 'Email, subdomain and people gathering',
                'category': 'recon',
                'wrapper': HarvesterWrapper
            },
            'enum4linux': {
                'command': 'enum4linux',
                'description': 'SMB enumeration tool',
                'category': 'network',
                'wrapper': Enum4linuxWrapper
            },
            'searchsploit': {
                'command': 'searchsploit',
                'description': 'Exploit database search',
                'category': 'exploitation',
                'wrapper': SearchsploitWrapper
            },
            'dirb': {
                'command': 'dirb',
                'description': 'Web content scanner',
                'category': 'web',
                'wrapper': DirbWrapper
            }
        }
        
    async def verify_tools(self) -> Dict[str, bool]:
        """Verify which Kali tools are available"""
        results = {}
        
        for tool_name, tool_config in self.tools_config.items():
            command = tool_config['command']
            if shutil.which(command):
                self.available_tools[tool_name] = tool_config
                results[tool_name] = True
                print(f"✅ {tool_name}: Available")
            else:
                results[tool_name] = False
                print(f"❌ {tool_name}: Not found")
                
        return results
        
    async def run_tool(self, tool_name: str, target: str, options: Dict = None) -> Dict:
        """Run a Kali tool with specified options"""
        if tool_name not in self.available_tools:
            return {
                'success': False,
                'error': f"Tool {tool_name} not available"
            }
            
        tool_config = self.available_tools[tool_name]
        wrapper_class = tool_config['wrapper']
        wrapper = wrapper_class()
        
        return await wrapper.run(target, options or {})


class BaseToolWrapper:
    """Base class for tool wrappers"""
    
    def __init__(self):
        self.command = None
        self.timeout = 300  # 5 minutes default
        
    async def run(self, target: str, options: Dict) -> Dict:
        """Run the tool"""
        raise NotImplementedError
        
    async def execute_command(self, command: List[str], timeout: int = None) -> Tuple[bool, str, str]:
        """Execute shell command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout or self.timeout
            )
            
            return process.returncode == 0, stdout.decode(), stderr.decode()
            
        except asyncio.TimeoutError:
            process.kill()
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)


class NmapWrapper(BaseToolWrapper):
    """Nmap tool wrapper"""
    
    def __init__(self):
        super().__init__()
        self.command = 'nmap'
        
    async def run(self, target: str, options: Dict) -> Dict:
        """Run Nmap scan"""
        scan_type = options.get('scan_type', 'normal')
        ports = options.get('ports', '1-65535')
        
        # Build command
        cmd = [self.command]
        
        # Scan type
        if scan_type == 'stealth':
            cmd.extend(['-sS'])
        elif scan_type == 'aggressive':
            cmd.extend(['-A', '-T4'])
        elif scan_type == 'vuln':
            cmd.extend(['--script', 'vuln'])
        elif scan_type == 'full':
            cmd.extend(['-sV', '-sC', '-O'])
            
        # Ports
        if ports != 'all':
            cmd.extend(['-p', ports])
            
        # Output format
        cmd.extend(['-oX', '-'])  # XML output to stdout
        
        # Target
        cmd.append(target)
        
        # Execute
        success, stdout, stderr = await self.execute_command(cmd)
        
        if success:
            # Parse XML output
            results = self.parse_nmap_xml(stdout)
            return {
                'success': True,
                'tool': 'nmap',
                'target': target,
                'results': results
            }
        else:
            return {
                'success': False,
                'error': stderr
            }
            
    def parse_nmap_xml(self, xml_data: str) -> Dict:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_data)
            results = {
                'hosts': [],
                'stats': {}
            }
            
            # Parse hosts
            for host in root.findall('host'):
                host_info = {
                    'address': host.find('address').get('addr'),
                    'status': host.find('status').get('state'),
                    'ports': []
                }
                
                # Parse ports
                ports_elem = host.find('ports')
                if ports_elem:
                    for port in ports_elem.findall('port'):
                        port_info = {
                            'port': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'state': port.find('state').get('state'),
                            'service': {}
                        }
                        
                        service = port.find('service')
                        if service:
                            port_info['service'] = {
                                'name': service.get('name', ''),
                                'product': service.get('product', ''),
                                'version': service.get('version', '')
                            }
                            
                        host_info['ports'].append(port_info)
                        
                results['hosts'].append(host_info)
                
            return results
            
        except Exception as e:
            return {'error': f"Failed to parse Nmap output: {e}"}


class SqlmapWrapper(BaseToolWrapper):
    """SQLMap tool wrapper"""
    
    def __init__(self):
        super().__init__()
        self.command = 'sqlmap'
        self.timeout = 600  # 10 minutes for SQLMap
        
    async def run(self, target: str, options: Dict) -> Dict:
        """Run SQLMap scan"""
        # Build command
        cmd = [self.command, '-u', target]
        
        # Options
        if options.get('batch'):
            cmd.append('--batch')  # Non-interactive mode
            
        if options.get('forms'):
            cmd.append('--forms')  # Test forms
            
        if options.get('level'):
            cmd.extend(['--level', str(options['level'])])
            
        if options.get('risk'):
            cmd.extend(['--risk', str(options['risk'])])
            
        if options.get('threads'):
            cmd.extend(['--threads', str(options['threads'])])
            
        # Database enumeration
        if options.get('dbs'):
            cmd.append('--dbs')
            
        if options.get('tables'):
            cmd.append('--tables')
            
        if options.get('dump'):
            cmd.append('--dump')
            
        # Output format
        cmd.extend(['--output-dir', '/tmp/sqlmap_output'])
        
        # Execute
        success, stdout, stderr = await self.execute_command(cmd, self.timeout)
        
        # Parse results
        vulnerabilities = self.parse_sqlmap_output(stdout)
        
        return {
            'success': success,
            'tool': 'sqlmap',
            'target': target,
            'vulnerabilities': vulnerabilities,
            'output': stdout if success else stderr
        }
        
    def parse_sqlmap_output(self, output: str) -> List[Dict]:
        """Parse SQLMap output for vulnerabilities"""
        vulnerabilities = []
        
        # Look for injection points
        if 'vulnerable' in output.lower():
            vuln_lines = [line for line in output.split('\n') if 'vulnerable' in line.lower()]
            for line in vuln_lines:
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'details': line.strip()
                })
                
        # Look for database information
        if 'available databases' in output.lower():
            db_section = output.split('available databases')[1].split('\n\n')[0]
            databases = [db.strip() for db in db_section.split('\n') if db.strip().startswith('[')]
            vulnerabilities.append({
                'type': 'Database Enumeration',
                'databases': databases
            })
            
        return vulnerabilities


class HydraWrapper(BaseToolWrapper):
    """Hydra password cracking tool wrapper"""
    
    def __init__(self):
        super().__init__()
        self.command = 'hydra'
        
    async def run(self, target: str, options: Dict) -> Dict:
        """Run Hydra password attack"""
        service = options.get('service', 'ssh')
        username = options.get('username')
        password_list = options.get('password_list', '/usr/share/wordlists/rockyou.txt')
        
        # Build command
        cmd = [self.command]
        
        # Username
        if username:
            cmd.extend(['-l', username])
        elif options.get('user_list'):
            cmd.extend(['-L', options['user_list']])
            
        # Password list
        cmd.extend(['-P', password_list])
        
        # Threads
        cmd.extend(['-t', str(options.get('threads', 4))])
        
        # Verbose
        if options.get('verbose'):
            cmd.append('-v')
            
        # Target and service
        cmd.extend([target, service])
        
        # Execute
        success, stdout, stderr = await self.execute_command(cmd)
        
        # Parse results
        credentials = self.parse_hydra_output(stdout)
        
        return {
            'success': success,
            'tool': 'hydra',
            'target': target,
            'service': service,
            'credentials': credentials,
            'output': stdout if success else stderr
        }
        
    def parse_hydra_output(self, output: str) -> List[Dict]:
        """Parse Hydra output for found credentials"""
        credentials = []
        
        # Look for successful logins
        pattern = r'\[(\d+)\]\[(\w+)\] host: ([\w\.\-]+)\s+login: (\w+)\s+password: (.+)'
        matches = re.findall(pattern, output)
        
        for match in matches:
            credentials.append({
                'host': match[2],
                'service': match[1],
                'username': match[3],
                'password': match[4]
            })
            
        return credentials


class GobusterWrapper(BaseToolWrapper):
    """Gobuster directory busting tool wrapper"""
    
    def __init__(self):
        super().__init__()
        self.command = 'gobuster'
        
    async def run(self, target: str, options: Dict) -> Dict:
        """Run Gobuster scan"""
        mode = options.get('mode', 'dir')
        wordlist = options.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        
        # Build command
        cmd = [self.command, mode]
        
        # Target
        cmd.extend(['-u', target])
        
        # Wordlist
        cmd.extend(['-w', wordlist])
        
        # Threads
        cmd.extend(['-t', str(options.get('threads', 10))])
        
        # Extensions (for dir mode)
        if mode == 'dir' and options.get('extensions'):
            cmd.extend(['-x', options['extensions']])
            
        # Status codes
        if options.get('status_codes'):
            cmd.extend(['-s', options['status_codes']])
            
        # Execute
        success, stdout, stderr = await self.execute_command(cmd)
        
        # Parse results
        findings = self.parse_gobuster_output(stdout)
        
        return {
            'success': success,
            'tool': 'gobuster',
            'target': target,
            'mode': mode,
            'findings': findings,
            'output': stdout if success else stderr
        }
        
    def parse_gobuster_output(self, output: str) -> List[Dict]:
        """Parse Gobuster output"""
        findings = []
        
        for line in output.split('\n'):
            if line.startswith('/') or line.startswith('Found:'):
                parts = line.split()
                if len(parts) >= 2:
                    findings.append({
                        'path': parts[0],
                        'status': parts[1] if len(parts) > 1 else '',
                        'size': parts[2] if len(parts) > 2 else ''
                    })
                    
        return findings


# Additional tool wrappers would be implemented similarly...
class MasscanWrapper(BaseToolWrapper):
    pass

class NiktoWrapper(BaseToolWrapper):
    pass

class MetasploitWrapper(BaseToolWrapper):
    pass

class JohnWrapper(BaseToolWrapper):
    pass

class AircrackWrapper(BaseToolWrapper):
    pass

class WpscanWrapper(BaseToolWrapper):
    pass

class BurpsuiteWrapper(BaseToolWrapper):
    pass

class HarvesterWrapper(BaseToolWrapper):
    pass

class Enum4linuxWrapper(BaseToolWrapper):
    pass

class SearchsploitWrapper(BaseToolWrapper):
    pass

class DirbWrapper(BaseToolWrapper):
    pass