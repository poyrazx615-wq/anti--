# Input Validation Module (continued)
import re
import ipaddress
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime
import validators
import dns.resolver
from pathlib import Path

class InputValidator:
    """Comprehensive input validation and sanitization"""
    
    def __init__(self):
        self.validation_rules = self._setup_validation_rules()
        
    def _setup_validation_rules(self) -> Dict:
        """Setup validation rules for different input types"""
        return {
            'url': {
                'pattern': r'^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)$',
                'max_length': 2048,
                'validator': self.validate_url
            },
            'domain': {
                'pattern': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$',
                'max_length': 253,
                'validator': self.validate_domain
            },
            'ip': {
                'pattern': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                'max_length': 45,  # IPv6 max length
                'validator': self.validate_ip
            },
            'email': {
                'pattern': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                'max_length': 254,
                'validator': self.validate_email
            },
            'port': {
                'pattern': r'^([1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$',
                'max_length': 5,
                'validator': self.validate_port
            },
            'path': {
                'pattern': r'^[a-zA-Z0-9_\-\.\/]+$',
                'max_length': 4096,
                'validator': self.validate_path
            },
            'username': {
                'pattern': r'^[a-zA-Z0-9_\-\.]{3,32}$',
                'max_length': 32,
                'validator': self.validate_username
            },
            'password': {
                'pattern': None,  # Complex validation in validator function
                'max_length': 128,
                'validator': self.validate_password
            },
            'alphanumeric': {
                'pattern': r'^[a-zA-Z0-9]+$',
                'max_length': 256,
                'validator': self.validate_alphanumeric
            },
            'numeric': {
                'pattern': r'^[0-9]+$',
                'max_length': 20,
                'validator': self.validate_numeric
            }
        }
        
    def validate(self, value: Any, input_type: str, **kwargs) -> Tuple[bool, Optional[str], Any]:
        """
        Validate input based on type
        
        Returns:
            Tuple of (is_valid, error_message, sanitized_value)
        """
        if value is None:
            return False, f"{input_type} cannot be None", None
            
        # Convert to string for validation
        value_str = str(value).strip()
        
        # Check if empty
        if not value_str and input_type != 'optional':
            return False, f"{input_type} cannot be empty", None
            
        # Get validation rules
        rules = self.validation_rules.get(input_type)
        if not rules:
            return False, f"Unknown input type: {input_type}", None
            
        # Check length
        max_length = kwargs.get('max_length', rules['max_length'])
        if len(value_str) > max_length:
            return False, f"{input_type} exceeds maximum length of {max_length}", None
            
        # Check pattern if exists
        if rules['pattern']:
            if not re.match(rules['pattern'], value_str):
                return False, f"Invalid {input_type} format", None
                
        # Run specific validator
        if rules['validator']:
            return rules['validator'](value_str, **kwargs)
            
        return True, None, value_str
        
    def validate_url(self, url: str, **kwargs) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate and sanitize URL"""
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            
            # Check scheme
            allowed_schemes = kwargs.get('allowed_schemes', ['http', 'https'])
            if parsed.scheme not in allowed_schemes:
                return False, f"URL scheme must be one of: {allowed_schemes}", None
                
            # Check for localhost/private IPs if not allowed
            if not kwargs.get('allow_local', False):
                try:
                    hostname = parsed.hostname
                    if hostname:
                        ip = ipaddress.ip_address(hostname)
                        if ip.is_private or ip.is_loopback:
                            return False, "Local/private URLs not allowed", None
                except ValueError:
                    # Not an IP, check for localhost
                    if parsed.hostname in ['localhost', '127.0.0.1', '::1']:
                        return False, "Localhost URLs not allowed", None
                        
            # Validate with validators library
            if not validators.url(url):
                return False, "Invalid URL format", None
                
            # Sanitize URL
            sanitized = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment
            ))
            
            return True, None, sanitized
            
        except Exception as e:
            return False, f"URL validation error: {e}", None
            
    def validate_domain(self, domain: str, **kwargs) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate domain name"""
        try:
            # Remove protocol if present
            domain = re.sub(r'^https?://', '', domain)
            
            # Remove path if present
            domain = domain.split('/')[0]
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            # Check with validators
            if not validators.domain(domain):
                return False, "Invalid domain format", None
                
            # Optional DNS resolution check
            if kwargs.get('check_dns', False):
                try:
                    dns.resolver.resolve(domain, 'A')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    return False, "Domain does not resolve", None
                except Exception:
                    pass  # DNS check failed, but domain format is valid
                    
            return True, None, domain.lower()
            
        except Exception as e:
            return False, f"Domain validation error: {e}", None
            
    def validate_ip(self, ip: str, **kwargs) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate IP address (IPv4 or IPv6)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check IP version
            allowed_versions = kwargs.get('versions', [4, 6])
            if ip_obj.version not in allowed_versions:
                return False, f"IP version {ip_obj.version} not allowed", None
                
            # Check for private/local IPs
            if not kwargs.get('allow_private', False):
                if ip_obj.is_private or ip_obj.is_loopback:
                    return False, "Private/loopback IPs not allowed", None
                    
            # Check for multicast
            if not kwargs.get('allow_multicast', False):
                if ip_obj.is_multicast:
                    return False, "Multicast IPs not allowed", None
                    
            return True, None, str(ip_obj)
            
        except ValueError as e:
            return False, f"Invalid IP address: {e}", None
            
    def validate_email(self, email: str, **kwargs) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate email address"""
        try:
            if not validators.email(email):
                return False, "Invalid email format", None
                
            # Additional checks
            local, domain = email.rsplit('@', 1)
            
            # Check local part length
            if len(local) > 64:
                return False, "Email local part too long", None
                
            # Check domain
            is_valid, error, _ = self.validate_domain(domain)
            if not is_valid:
                return False, f"Invalid email domain: {error}", None
                
            return True, None, email.lower()
            
        except Exception as e:
            return False, f"Email validation error: {e}", None
            
    def validate_port(self, port: Union[str, int], **kwargs) -> Tuple[bool, Optional[str], Optional[int]]:
        """Validate port number"""
        try:
            port_num = int(port)
            
            if port_num < 1 or port_num > 65535:
                return False, "Port must be between 1 and 65535", None
                
            # Check for privileged ports
            if port_num < 1024 and not kwargs.get('allow_privileged', False):
                return False, "Privileged ports (< 1024) not allowed", None
                
            return True, None, port_num
            
        except ValueError:
            return False, "Port must be a number", None
            
    def validate_path(self, path: str, **kwargs) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate file path"""
        try:
            # Check for path traversal attempts
            if '..' in path or path.startswith('/etc/') or path.startswith('/root/'):
                return False, "Path traversal detected", None
                
            # Check for null bytes
            if '\x00' in path:
                return False, "Null bytes not allowed in path", None
                
            # Validate path exists if required
            if kwargs.get('must_exist', False):
                path_obj = Path(path)
                if not path_obj.exists():
                    return False, "Path does not exist", None
                    
            # Check allowed extensions
            allowed_extensions = kwargs.get('allowed_extensions')
            if allowed_extensions:
                ext = Path(path).suffix.lower()
                if ext not in allowed_extensions:
                    return False, f"File extension must be one of: {allowed_extensions}", None
                    
            return True, None, path
            
        except Exception as e:
            return False, f"Path validation error: {e}", None
            
    def validate_username(self, username: str, **kwargs) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate username"""
        min_length = kwargs.get('min_length', 3)
        max_length = kwargs.get('max_length', 32)
        
        if len(username) < min_length:
            return False, f"Username must be at least {min_length} characters", None
            
        if len(username) > max_length:
            return False, f"Username must not exceed {max_length} characters", None
            
        # Check for reserved usernames
        reserved = kwargs.get('reserved', ['admin', 'root', 'administrator', 'system'])
        if username.lower() in reserved:
            return False, "Username is reserved", None
            
        return True, None, username.lower()
        
    def validate_password(self, password: str, **kwargs) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate password strength"""
        min_length = kwargs.get('min_length', 12)
        
        errors = []
        
        if len(password) < min_length:
            errors.append(f"Password must be at least {min_length} characters")
            
        if kwargs.get('require_uppercase', True) and not re.search(r'[A-Z]', password):
            errors.append("Password must contain uppercase letters")
            
        if kwargs.get('require_lowercase', True) and not re.search(r'[a-z]', password):
            errors.append("Password must contain lowercase letters")
            
        if kwargs.get('require_numbers', True) and not re.search(r'\d', password):
            errors.append("Password must contain numbers")
            
        if kwargs.get('require_special', True) and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain special characters")
            
        # Check for common passwords
        common_passwords = ['password', '123456', 'admin', 'letmein', 'welcome']
        if password.lower() in common_passwords:
            errors.append("Password is too common")
            
        if errors:
            return False, '; '.join(errors), None
            
        return True, None, password  # Don't modify password
        
    def validate_alphanumeric(self, value: str, **kwargs) -> Tuple[bool, Optional[str], Optional[str]]:
        """Validate alphanumeric string"""
        if not value.isalnum():
            return False, "Value must be alphanumeric", None
            
        return True, None, value
        
    def validate_numeric(self, value: str, **kwargs) -> Tuple[bool, Optional[str], Optional[int]]:
        """Validate numeric value"""
        try:
            num = int(value)
            
            min_val = kwargs.get('min_value')
            max_val = kwargs.get('max_value')
            
            if min_val is not None and num < min_val:
                return False, f"Value must be at least {min_val}", None
                
            if max_val is not None and num > max_val:
                return False, f"Value must not exceed {max_val}", None
                
            return True, None, num
            
        except ValueError:
            return False, "Value must be numeric", None
            
    def sanitize(self, value: str, sanitize_type: str = 'general') -> str:
        """Sanitize input based on type"""
        if not value:
            return ""
            
        # Remove null bytes
        value = value.replace('\x00', '')
        
        if sanitize_type == 'html':
            # HTML escape
            value = (value
                    .replace('&', '&amp;')
                    .replace('<', '&lt;')
                    .replace('>', '&gt;')
                    .replace('"', '&quot;')
                    .replace("'", '&#39;'))
                    
        elif sanitize_type == 'sql':
            # SQL escape
            value = value.replace("'", "''")
            value = value.replace("\\", "\\\\")
            value = value.replace("\n", "\\n")
            value = value.replace("\r", "\\r")
            value = value.replace("\t", "\\t")
            
        elif sanitize_type == 'shell':
            # Shell escape
            dangerous_chars = ';|&$>`\\"\'\\n\\r'
            for char in dangerous_chars:
                value = value.replace(char, '')
                
        elif sanitize_type == 'filename':
            # Filename sanitization
            value = re.sub(r'[^\w\s\-\.]', '', value)
            value = re.sub(r'\.{2,}', '.', value)
            
        elif sanitize_type == 'json':
            # JSON escape
            value = value.replace('\\', '\\\\')
            value = value.replace('"', '\\"')
            value = value.replace('\n', '\\n')
            value = value.replace('\r', '\\r')
            value = value.replace('\t', '\\t')
            
        else:
            # General sanitization
            value = re.sub(r'[<>\"\'`;&|\\]', '', value)
            
        return value.strip()
        
    def validate_scan_target(self, target: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Special validation for scan targets"""
        # Try to determine target type
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
            # IP address
            return self.validate_ip(target, allow_private=True)
        elif target.startswith('http://') or target.startswith('https://'):
            # URL
            return self.validate_url(target, allow_local=True)
        else:
            # Domain
            return self.validate_domain(target)
            
    def batch_validate(self, data: Dict[str, Any], rules: Dict[str, str]) -> Tuple[bool, Dict[str, str], Dict[str, Any]]:
        """
        Validate multiple inputs at once
        
        Args:
            data: Dictionary of key-value pairs to validate
            rules: Dictionary of key-validation_type pairs
            
        Returns:
            Tuple of (all_valid, errors_dict, sanitized_data_dict)
        """
        errors = {}
        sanitized = {}
        all_valid = True
        
        for key, value in data.items():
            if key in rules:
                is_valid, error, clean_value = self.validate(value, rules[key])
                if not is_valid:
                    errors[key] = error
                    all_valid = False
                else:
                    sanitized[key] = clean_value
            else:
                sanitized[key] = value
                
        return all_valid, errors, sanitized