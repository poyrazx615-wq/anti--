# FastAPI Application with Web GUI
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import os
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def create_app():
    """Create FastAPI application with GUI"""
    
    app = FastAPI(
        title="Kali Security Platform",
        description="Professional Penetration Testing Framework",
        version="5.0.0"
    )
    
    # CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Create necessary directories
    Path("outputs").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    
    # Import routes with error handling
    try:
        from api.routes import exploit_advisor, osint, security_tools
        
        # Add routes
        app.include_router(exploit_advisor.router, prefix="/exploit-advisor", tags=["Exploit Advisor"])
        app.include_router(osint.router, prefix="/osint", tags=["OSINT Tools"])
        app.include_router(security_tools.router, prefix="/security-tools", tags=["Security Tools"])
    except ImportError as e:
        print(f"Warning: Could not import routes: {e}")
    
    # Root endpoint
    @app.get("/", response_class=HTMLResponse)
    async def home():
        """Ana sayfa - Dashboard"""
        return HTMLResponse(content=DASHBOARD_HTML)
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {"status": "healthy", "version": "5.0.0"}
    
    return app

# Modern Dashboard HTML
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali Security Platform - Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .gradient-bg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .glass-effect {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
    </style>
</head>
<body class="gradient-bg min-h-screen text-white">
    <div class="min-h-screen">
        <!-- Navigation -->
        <nav class="glass-effect border-b border-white/20">
            <div class="container mx-auto px-6 py-4">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <i class="fas fa-shield-alt text-3xl text-purple-400"></i>
                        <h1 class="text-2xl font-bold">Kali Security Platform</h1>
                    </div>
                    <div class="flex space-x-6">
                        <a href="/" class="text-purple-300">Dashboard</a>
                        <a href="/security-tools" class="hover:text-purple-300 transition">Security Tools</a>
                        <a href="/osint" class="hover:text-purple-300 transition">OSINT</a>
                        <a href="/exploit-advisor" class="hover:text-purple-300 transition">Exploits</a>
                    </div>
                </div>
            </div>
        </nav>

        <!-- Main Content -->
        <div class="container mx-auto px-6 py-8">
            <!-- Stats Cards -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                <div class="glass-effect rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-300 text-sm">Toplam Araç</p>
                            <p class="text-3xl font-bold mt-2">130+</p>
                        </div>
                        <div class="text-purple-400">
                            <i class="fas fa-tools text-4xl"></i>
                        </div>
                    </div>
                </div>

                <div class="glass-effect rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-300 text-sm">OSINT Araçları</p>
                            <p class="text-3xl font-bold mt-2">17</p>
                        </div>
                        <div class="text-blue-400">
                            <i class="fas fa-search text-4xl"></i>
                        </div>
                    </div>
                </div>

                <div class="glass-effect rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-300 text-sm">Exploit DB</p>
                            <p class="text-3xl font-bold mt-2">Ready</p>
                        </div>
                        <div class="text-red-400">
                            <i class="fas fa-bomb text-4xl"></i>
                        </div>
                    </div>
                </div>

                <div class="glass-effect rounded-xl p-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <p class="text-gray-300 text-sm">Sistem Durumu</p>
                            <p class="text-3xl font-bold mt-2 text-green-400">Aktif</p>
                        </div>
                        <div class="text-green-400">
                            <i class="fas fa-server text-4xl"></i>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Quick Access -->
            <div class="glass-effect rounded-xl p-6">
                <h3 class="text-xl font-semibold mb-4">Hızlı Erişim</h3>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <a href="/security-tools" class="bg-purple-600 hover:bg-purple-700 p-4 rounded-lg text-center transition">
                        <i class="fas fa-terminal text-2xl mb-2"></i>
                        <p>Security Tools</p>
                    </a>
                    <a href="/osint" class="bg-blue-600 hover:bg-blue-700 p-4 rounded-lg text-center transition">
                        <i class="fas fa-user-secret text-2xl mb-2"></i>
                        <p>OSINT Framework</p>
                    </a>
                    <a href="/exploit-advisor" class="bg-red-600 hover:bg-red-700 p-4 rounded-lg text-center transition">
                        <i class="fas fa-bug text-2xl mb-2"></i>
                        <p>Exploit Advisor</p>
                    </a>
                    <a href="/security-tools" class="bg-green-600 hover:bg-green-700 p-4 rounded-lg text-center transition">
                        <i class="fas fa-file-alt text-2xl mb-2"></i>
                        <p>Reports</p>
                    </a>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''
