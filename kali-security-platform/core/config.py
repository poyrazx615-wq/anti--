# Core Configuration Module
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import secrets

@dataclass
class Config:
    """Platform configuration"""
    
    # Server Configuration
    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    DEBUG: bool = False
    SECRET_KEY: str = field(default_factory=lambda: secrets.token_hex(32))
    
    # SSL Configuration
    SSL_ENABLED: bool = True
    SSL_CERT_FILE: str = "/etc/nginx/ssl/platform.crt"
    SSL_KEY_FILE: str = "/etc/nginx/ssl/platform.key"
    SSL_VERIFY: bool = True  # Enable SSL certificate verification
    
    # Database Configuration
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_NAME: str = "security_platform"
    DB_USER: str = "antisecurity"
    DB_PASSWORD: str = "AntiSec2024!"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    
    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None
    REDIS_POOL_SIZE: int = 10
    
    # Rate Limiting
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/hour"
    RATE_LIMIT_SCAN: str = "10/hour"
    RATE_LIMIT_API: str = "1000/hour"
    RATE_LIMIT_AUTH: str = "5/minute"
    
    # Security Settings
    CORS_ORIGINS: list = field(default_factory=lambda: ["https://localhost"])
    JWT_SECRET: str = field(default_factory=lambda: secrets.token_hex(32))
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_HOURS: int = 24
    PASSWORD_MIN_LENGTH: int = 12
    PASSWORD_REQUIRE_SPECIAL: bool = True
    PASSWORD_REQUIRE_NUMBERS: bool = True
    PASSWORD_REQUIRE_UPPERCASE: bool = True
    
    # Scanning Configuration
    SCAN_TIMEOUT: int = 300  # 5 minutes
    SCAN_MAX_THREADS: int = 50
    SCAN_ASYNC_WORKERS: int = 10
    SCAN_RATE_LIMIT: int = 100  # requests per second
    
    # Cache Configuration
    CACHE_TTL_DEFAULT: int = 3600  # 1 hour
    CACHE_TTL_SCAN: int = 86400  # 24 hours
    CACHE_TTL_REPORT: int = 604800  # 7 days
    
    # File Storage
    UPLOAD_DIR: str = "/opt/kali-security-platform/uploads"
    REPORT_DIR: str = "/opt/kali-security-platform/reports"
    LOG_DIR: str = "/opt/kali-security-platform/logs"
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024  # 100MB
    
    # Kali Tools Configuration
    KALI_TOOLS_PATH: str = "/usr/bin:/usr/local/bin:/usr/share"
    KALI_WORDLISTS: str = "/usr/share/wordlists"
    KALI_EXPLOITS: str = "/usr/share/exploitdb"
    KALI_METASPLOIT: str = "/usr/share/metasploit-framework"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_ROTATION: str = "1 day"
    LOG_RETENTION: int = 30  # days
    
    # Performance
    ENABLE_PROFILING: bool = False
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    
    # Email Configuration (for alerts)
    SMTP_ENABLED: bool = False
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "security@antisecurity.local"
    
    def __post_init__(self):
        """Post initialization setup"""
        # Create directories if they don't exist
        for dir_path in [self.UPLOAD_DIR, self.REPORT_DIR, self.LOG_DIR]:
            Path(dir_path).mkdir(parents=True, exist_ok=True)
            
    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables"""
        config = cls()
        
        for field_name in config.__dataclass_fields__:
            env_var = f"SECURITY_{field_name}"
            if env_var in os.environ:
                value = os.environ[env_var]
                field_type = config.__dataclass_fields__[field_name].type
                
                # Type conversion
                if field_type == bool:
                    value = value.lower() in ('true', '1', 'yes')
                elif field_type == int:
                    value = int(value)
                elif field_type == list:
                    value = json.loads(value)
                    
                setattr(config, field_name, value)
                
        return config
        
    @classmethod
    def from_file(cls, file_path: str) -> "Config":
        """Load configuration from JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        return cls(**data)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary (excluding sensitive data)"""
        result = {}
        sensitive_fields = {'DB_PASSWORD', 'JWT_SECRET', 'SECRET_KEY', 'SMTP_PASSWORD'}
        
        for field_name in self.__dataclass_fields__:
            if field_name not in sensitive_fields:
                result[field_name] = getattr(self, field_name)
            else:
                result[field_name] = "***HIDDEN***"
                
        return result
        
    def validate(self) -> bool:
        """Validate configuration"""
        errors = []
        
        # Check SSL files exist if SSL is enabled
        if self.SSL_ENABLED:
            if not Path(self.SSL_CERT_FILE).exists():
                errors.append(f"SSL certificate not found: {self.SSL_CERT_FILE}")
            if not Path(self.SSL_KEY_FILE).exists():
                errors.append(f"SSL key not found: {self.SSL_KEY_FILE}")
                
        # Check password requirements
        if self.PASSWORD_MIN_LENGTH < 8:
            errors.append("Password minimum length must be at least 8")
            
        # Check rate limits
        if self.SCAN_MAX_THREADS > 100:
            errors.append("Maximum threads cannot exceed 100")
            
        if errors:
            for error in errors:
                print(f"Configuration Error: {error}")
            return False
            
        return True