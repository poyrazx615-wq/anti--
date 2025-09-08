# Security Manager Module
import ssl
import secrets
import hashlib
import jwt
import re
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Any
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64

class SecurityManager:
    """Comprehensive security management"""
    
    def __init__(self, config):
        self.config = config
        self.fernet = None
        self.ssl_context = None
        
    async def initialize(self):
        """Initialize security components"""
        # Setup encryption
        self._setup_encryption()
        
        # Setup SSL context
        if self.config.SSL_ENABLED:
            self._setup_ssl_context()
            
    def _setup_encryption(self):
        """Setup Fernet encryption"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'stable_salt',  # In production, use random salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.config.SECRET_KEY.encode()))
        self.fernet = Fernet(key)
        
    def _setup_ssl_context(self):
        """Setup SSL context with certificate verification"""
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        if self.config.SSL_VERIFY:
            self.ssl_context.check_hostname = True
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        else:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            
        # Load certificate and key
        if self.config.SSL_CERT_FILE and self.config.SSL_KEY_FILE:
            self.ssl_context.load_cert_chain(
                self.config.SSL_CERT_FILE,
                self.config.SSL_KEY_FILE
            )
            
        # Set strong ciphers
        self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        # Set minimum TLS version
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        
    def validate_password(self, password: str) -> tuple[bool, List[str]]:
        """Validate password strength"""
        errors = []
        
        if len(password) < self.config.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {self.config.PASSWORD_MIN_LENGTH} characters")
            
        if self.config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain uppercase letters")
            
        if self.config.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', password):
            errors.append("Password must contain numbers")
            
        if self.config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain special characters")
            
        return len(errors) == 0, errors
        
    def generate_token(self, user_id: str, extra_claims: Dict = None) -> str:
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=self.config.JWT_EXPIRY_HOURS),
            'iat': datetime.utcnow(),
            'jti': secrets.token_hex(16)
        }
        
        if extra_claims:
            payload.update(extra_claims)
            
        return jwt.encode(payload, self.config.JWT_SECRET, algorithm=self.config.JWT_ALGORITHM)
        
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(
                token,
                self.config.JWT_SECRET,
                algorithms=[self.config.JWT_ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
            
    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.fernet.encrypt(data.encode()).decode()
        
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.fernet.decrypt(encrypted_data.encode()).decode()
        
    def generate_api_key(self) -> str:
        """Generate secure API key"""
        return secrets.token_urlsafe(32)
        
    def sanitize_input(self, input_str: str, input_type: str = 'general') -> str:
        """Sanitize user input based on type"""
        if not input_str:
            return ""
            
        # Remove null bytes
        input_str = input_str.replace('\x00', '')
        
        # Type-specific sanitization
        if input_type == 'url':
            # URL sanitization
            input_str = re.sub(r'[^\w\s\-\.\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\%]', '', input_str)
        elif input_type == 'domain':
            # Domain sanitization
            input_str = re.sub(r'[^\w\.\-]', '', input_str)
        elif input_type == 'ip':
            # IP address sanitization
            input_str = re.sub(r'[^\d\.\:]', '', input_str)
        elif input_type == 'filename':
            # Filename sanitization
            input_str = re.sub(r'[^\w\s\-\.]', '', input_str)
            input_str = re.sub(r'\.{2,}', '.', input_str)  # Prevent directory traversal
        else:
            # General sanitization - remove potentially dangerous characters
            input_str = re.sub(r'[<>\"\'`;&|\\]', '', input_str)
            
        return input_str.strip()
        
    def validate_csrf_token(self, token: str, session_token: str) -> bool:
        """Validate CSRF token"""
        return secrets.compare_digest(token, session_token)
        
    def generate_csrf_token(self) -> str:
        """Generate CSRF token"""
        return secrets.token_hex(32)
        
    def check_sql_injection(self, input_str: str) -> bool:
        """Check for potential SQL injection patterns"""
        sql_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"(\bUPDATE\b.*\bSET\b)",
            r"(--|\#|\/\*|\*\/)",
            r"(\bOR\b.*=.*)",
            r"(\bAND\b.*=.*)",
            r"(\'.*\bOR\b.*\')",
            r"(\bEXEC\b|\bEXECUTE\b)",
            r"(\bSCRIPT\b)",
            r"(<.*>)",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
                
        return False
        
    def check_xss_attempt(self, input_str: str) -> bool:
        """Check for potential XSS patterns"""
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<img[^>]*on\w+",
            r"alert\s*\(",
            r"prompt\s*\(",
            r"confirm\s*\(",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                return True
                
        return False
        
    def get_ssl_context(self):
        """Get configured SSL context"""
        return self.ssl_context