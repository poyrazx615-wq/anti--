#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kali Security Platform - Main Application (FIXED)
"""

import uvicorn
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def create_app():
    """Create and configure FastAPI application"""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles
    
    # Initialize core components
    from core.config import Config
    from core.database import DatabaseManager
    from core.cache import CacheManager
    from core.security import SecurityManager
    from core.rate_limiter import RateLimiter
    from core.validator import InputValidator
    
    # Load configuration
    config = Config.from_env() if Path('.env').exists() else Config()
    
    # Create FastAPI app
    app = FastAPI(
        title="Kali Security Platform",
        description="Professional Penetration Testing Framework",
        version="5.0.0"
    )
    
    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, use specific origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Create directories if not exist
    Path("web/static").mkdir(parents=True, exist_ok=True)
    Path("web/templates").mkdir(parents=True, exist_ok=True)
    Path("outputs").mkdir(parents=True, exist_ok=True)
    Path("logs").mkdir(parents=True, exist_ok=True)
    
    # Mount static files if directory exists
    if Path("web/static").exists():
        app.mount("/static", StaticFiles(directory="web/static"), name="static")
    
    # Import and register routes
    try:
        from api.routes import security_tools, osint, exploit