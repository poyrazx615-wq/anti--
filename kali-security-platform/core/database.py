# Database Manager Module
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from contextlib import asynccontextmanager

import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Integer, DateTime, Text, JSON, Boolean, ForeignKey, select, update, delete
import uuid

class Base(DeclarativeBase):
    """Base class for all database models"""
    pass

class User(Base):
    __tablename__ = 'users'
    
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    api_key: Mapped[Optional[str]] = mapped_column(String(64), unique=True, nullable=True)

class ScanJob(Base):
    __tablename__ = 'scan_jobs'
    
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String, ForeignKey('users.id'))
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default='pending')
    progress: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    config: Mapped[Dict] = mapped_column(JSON, default=dict)
    results: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String, ForeignKey('scan_jobs.id'))
    type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    affected_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    evidence: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cve: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Integer, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = 'reports'
    
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_job_id: Mapped[str] = mapped_column(String, ForeignKey('scan_jobs.id'))
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    file_path: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey('users.id'), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[Optional[Dict]] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class DatabaseManager:
    """Database connection and operations manager"""
    
    def __init__(self, config):
        self.config = config
        self.engine = None
        self.async_session = None
        self.pool = None
        
    async def initialize(self):
        """Initialize database connections"""
        # PostgreSQL connection string
        db_url = f"postgresql+asyncpg://{self.config.DB_USER}:{self.config.DB_PASSWORD}@{self.config.DB_HOST}:{self.config.DB_PORT}/{self.config.DB_NAME}"
        
        # Create async engine
        self.engine = create_async_engine(
            db_url,
            pool_size=self.config.DB_POOL_SIZE,
            max_overflow=self.config.DB_MAX_OVERFLOW,
            pool_pre_ping=True,
            echo=False
        )
        
        # Create session factory
        self.async_session = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Create tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            
        # Create direct connection pool for raw queries
        self.pool = await asyncpg.create_pool(
            host=self.config.DB_HOST,
            port=self.config.DB_PORT,
            user=self.config.DB_USER,
            password=self.config.DB_PASSWORD,
            database=self.config.DB_NAME,
            min_size=10,
            max_size=self.config.DB_POOL_SIZE
        )
        
    @asynccontextmanager
    async def get_session(self):
        """Get database session"""
        async with self.async_session() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
                
    async def create_user(self, user_data: Dict) -> User:
        """Create new user"""
        async with self.get_session() as session:
            user = User(**user_data)
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return user
            
    async def get_user(self, user_id: str = None, username: str = None, email: str = None) -> Optional[User]:
        """Get user by ID, username, or email"""
        async with self.get_session() as session:
            query = select(User)
            
            if user_id:
                query = query.where(User.id == user_id)
            elif username:
                query = query.where(User.username == username)
            elif email:
                query = query.where(User.email == email)
            else:
                return None
                
            result = await session.execute(query)
            return result.scalar_one_or_none()
            
    async def create_scan_job(self, scan_data: Dict) -> ScanJob:
        """Create new scan job"""
        async with self.get_session() as session:
            scan = ScanJob(**scan_data)
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
            return scan
            
    async def update_scan_job(self, scan_id: str, updates: Dict) -> Optional[ScanJob]:
        """Update scan job"""
        async with self.get_session() as session:
            stmt = update(ScanJob).where(ScanJob.id == scan_id).values(**updates)
            await session.execute(stmt)
            await session.commit()
            
            # Get updated scan
            result = await session.execute(select(ScanJob).where(ScanJob.id == scan_id))
            return result.scalar_one_or_none()
            
    async def get_scan_jobs(self, user_id: str = None, status: str = None, limit: int = 100) -> List[ScanJob]:
        """Get scan jobs with filters"""
        async with self.get_session() as session:
            query = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
            
            if user_id:
                query = query.where(ScanJob.user_id == user_id)
            if status:
                query = query.where(ScanJob.status == status)
                
            result = await session.execute(query)
            return result.scalars().all()
            
    async def add_vulnerability(self, vuln_data: Dict) -> Vulnerability:
        """Add vulnerability finding"""
        async with self.get_session() as session:
            vuln = Vulnerability(**vuln_data)
            session.add(vuln)
            await session.commit()
            await session.refresh(vuln)
            return vuln
            
    async def get_vulnerabilities(self, scan_job_id: str = None, severity: str = None) -> List[Vulnerability]:
        """Get vulnerabilities with filters"""
        async with self.get_session() as session:
            query = select(Vulnerability).order_by(Vulnerability.discovered_at.desc())
            
            if scan_job_id:
                query = query.where(Vulnerability.scan_job_id == scan_job_id)
            if severity:
                query = query.where(Vulnerability.severity == severity)
                
            result = await session.execute(query)
            return result.scalars().all()
            
    async def log_audit(self, audit_data: Dict):
        """Log audit event"""
        async with self.get_session() as session:
            log = AuditLog(**audit_data)
            session.add(log)
            await session.commit()
            
    async def get_statistics(self) -> Dict:
        """Get platform statistics"""
        async with self.pool.acquire() as conn:
            stats = {}
            
            # Total scans
            total_scans = await conn.fetchval("SELECT COUNT(*) FROM scan_jobs")
            stats['total_scans'] = total_scans
            
            # Active scans
            active_scans = await conn.fetchval(
                "SELECT COUNT(*) FROM scan_jobs WHERE status IN ('running', 'pending')"
            )
            stats['active_scans'] = active_scans
            
            # Total vulnerabilities
            total_vulns = await conn.fetchval("SELECT COUNT(*) FROM vulnerabilities")
            stats['total_vulnerabilities'] = total_vulns
            
            # Vulnerability breakdown
            vuln_breakdown = await conn.fetch(
                "SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity"
            )
            stats['vulnerability_breakdown'] = {row['severity']: row['count'] for row in vuln_breakdown}
            
            # Total users
            total_users = await conn.fetchval("SELECT COUNT(*) FROM users")
            stats['total_users'] = total_users
            
            # Recent activity
            recent_scans = await conn.fetchval(
                "SELECT COUNT(*) FROM scan_jobs WHERE created_at > NOW() - INTERVAL '24 hours'"
            )
            stats['scans_last_24h'] = recent_scans
            
            return stats
            
    async def close(self):
        """Close database connections"""
        if self.engine:
            await self.engine.dispose()
        if self.pool:
            await self.pool.close()