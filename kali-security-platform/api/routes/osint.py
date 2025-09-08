# OSINT Tools Web Interface
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from typing import Dict, List, Optional
from modules.osint.osint_framework import osint_framework as OSINTFramework
import json

router = APIRouter()
osint_framework = OSINTFramework

# OSINT Dashboard HTML
OSINT_HTML = '''
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Framework - Açık Kaynak İstihbarat</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-bash.min.js"></script>
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
        .tool-card {
            transition: all 0.3s ease;
        }
        .tool-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }
        .terminal-style {
            background: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Consolas', 'Monaco', monospace;
        }
        .scenario-step {
            position: relative;
            padding-left: 40px;
        }
        .scenario-step::before {
            content: '';
            position: absolute;
            left: 15px;
            top: 30px;
            bottom: -20px;
            width: 2px;
            background: linear-gradient(to bottom, #667eea, #764ba2);
        }
        .scenario-step:last-child::before {
            display: none;
        }
        .step-number {
            position: absolute;
            left: 0;
            top: 0;
            width: 30px;
            height: 30px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 14px;
        }
    </style>
</head>
<body class="gradient-bg min-h-screen text-white">
    <!-- Navigation -->
    <nav class="glass-effect border-b border-white/20 sticky top-0 z-50">
        <div class="container mx-auto px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                    <i class="fas fa-search-location text-3xl text-blue-400"></i>
                    <h1 class="text-2xl font-bold">OSINT Framework</h1>
                    <span class="bg-green-600 px-2 py-1 rounded text-xs">v2.0</span>
                </div>
                <div class="flex space-x-6">
                    <a href="/" class="hover:text-purple-300 transition">Dashboard</a>
                    <a href="/osint" class="text-purple-300">OSINT Tools</a>
                    <a href="/exploit-advisor" class="hover:text-purple-300 transition">Exploit Advisor</a>
                </div>
            </div>
        </div>
    </nav>

    <div class="container mx-auto px-6 py-8">
        <!-- Header Section -->
        <div class="glass-effect rounded-xl p-6 mb-8">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-3xl font-bold">
                    <i class="fas fa-user-secret mr-3 text-blue-400"></i>
                    Açık Kaynak İstihbarat Araçları
                </h2>
                <div class="flex space-x-3">
                    <button onclick="showScenarios()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition">
                        <i class="fas fa-route mr-2"></i>Senaryolar
                    </button>
                    <button onclick="showQuickStart()" class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded-lg transition">
                        <i class="fas fa-rocket mr-2"></i>Hızlı Başlangıç
                    </button>
                </div>
            </div>
            <p class="text-gray-300">
                Her duruma özel OSINT araçları, kullanım senaryoları ve adım adım rehberler. 
                <span class="text-yellow-400">Eğitimde göstermek için hazır!</span>
            </p>
        </div>

        <!-- Quick Search Section -->
        <div class="glass-effect rounded-xl p-6 mb-8">
            <h3 class="text-xl font-semibold mb-4">
                <i class="fas fa-magic mr-2 text-yellow-400"></i>
                Ne Arıyorsunuz?
            </h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                <button onclick="filterByNeed('email')" class="bg-purple-600/30 hover:bg-purple-600/50 p-3 rounded-lg transition">
                    <i class="fas fa-envelope text-2xl mb-2"></i>
                    <p>Email Adresleri</p>
                </button>
                <button onclick="filterByNeed('subdomain')" class="bg-blue-600/30 hover:bg-blue-600/50 p-3 rounded-lg transition">
                    <i class="fas fa-sitemap text-2xl mb-2"></i>
                    <p>Subdomain</p>
                </button>
                <button onclick="filterByNeed('person')" class="bg-green-600/30 hover:bg-green-600/50 p-3 rounded-lg transition">
                    <i class="fas fa-user text-2xl mb-2"></i>
                    <p>Kişi Bilgisi</p>
                </button>
                <button onclick="filterByNeed('leak')" class="bg-red-600/30 hover:bg-red-600/50 p-3 rounded-lg transition">
                    <i class="fas fa-database text-2xl mb-2"></i>
                    <p>Data Breach</p>
                </button>
            </div>
        </div>

        <!-- Scenarios Section -->
        <div id="scenarios-section" class="glass-effect rounded-xl p-6 mb-8 hidden">
            <h3 class="text-2xl font-semibold mb-6">
                <i class="fas fa-project-diagram mr-2 text-green-400"></i>
                Kullanım Senaryoları
            </h3>
            <div id="scenarios-content"></div>
        </div>

        <!-- Tools Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="tools-grid">
            <!-- Tools will be loaded here dynamically -->
        </div>
    </div>

    <script>
        // OSINT Tools Database
        const osintTools = {
            'SHODAN': {
                name: 'Shodan',
                category: 'IoT & Device Search',
                description: 'İnternete bağlı cihazları tarayan arama motoru',
                useCases: [
                    'Açık portları bulma',
                    'Default şifreli cihazlar',
                    'IoT cihaz keşfi',
                    'SSL sertifika analizi'
                ],
                commands: [
                    'shodan init API_KEY',
                    'shodan host 8.8.8.8',
                    'shodan search hostname:example.com',
                    'shodan search "default password" country:TR'
                ],
                icon: 'fa-satellite-dish',
                color: 'red'
            },
            'CENSYS': {
                name: 'Censys',
                category: 'Internet Scanner',
                description: 'İnternet genelinde cihaz ve sertifika taraması',
                useCases: [
                    'SSL/TLS sertifika analizi',
                    'Subdomain keşfi',
                    'Banner grabbing',
                    'IPv6 host discovery'
                ],
                commands: [
                    'censys search "parsed.names: example.com"',
                    'censys search "ip:192.168.1.0/24"',
                    'censys search "services.port:9200"'
                ],
                icon: 'fa-globe',
                color: 'blue'
            },
            'AMASS': {
                name: 'Amass',
                category: 'Subdomain Enumeration',
                description: 'OWASP subdomain keşif aracı',
                useCases: [
                    'Subdomain bulma',
                    'DNS kayıtları',
                    'ASN keşfi',
                    'IP aralıkları'
                ],
                commands: [
                    'amass enum -d example.com',
                    'amass enum -passive -d example.com',
                    'amass intel -d example.com -whois'
                ],
                icon: 'fa-network-wired',
                color: 'green'
            },
            'THEHARVESTER': {
                name: 'theHarvester',
                category: 'Email Gathering',
                description: 'Email adresleri ve subdomain toplama',
                useCases: [
                    'Email toplama',
                    'Employee enumeration',
                    'Virtual host bulma',
                    'DNS brute force'
                ],
                commands: [
                    'theHarvester -d example.com -b all',
                    'theHarvester -d example.com -b google',
                    'theHarvester -d example.com -c -b all'
                ],
                icon: 'fa-envelope',
                color: 'purple'
            },
            'SHERLOCK': {
                name: 'Sherlock',
                category: 'Username OSINT',
                description: '300+ sitede username araması',
                useCases: [
                    'Social media profil bulma',
                    'Username availability',
                    'Online presence mapping',
                    'Identity verification'
                ],
                commands: [
                    'sherlock username123',
                    'sherlock --json output.json username',
                    'sherlock --site-list'
                ],
                icon: 'fa-user-secret',
                color: 'yellow'
            },
            'PHONEINFOGA': {
                name: 'PhoneInfoga',
                category: 'Phone OSINT',
                description: 'Telefon numarası analizi',
                useCases: [
                    'Carrier identification',
                    'Location finding',
                    'Social media search',
                    'Scam detection'
                ],
                commands: [
                    'phoneinfoga scan -n +905551234567',
                    'phoneinfoga serve -p 5000'
                ],
                icon: 'fa-phone',
                color: 'orange'
            }
        };

        // Load tools on page load
        document.addEventListener('DOMContentLoaded', () => {
            loadAllTools();
        });

        function loadAllTools() {
            const grid = document.getElementById('tools-grid');
            grid.innerHTML = '';
            
            Object.keys(osintTools).forEach(key => {
                const tool = osintTools[key];
                grid.innerHTML += createToolCard(tool);
            });
        }

        function createToolCard(tool) {
            const colorClasses = {
                'red': 'bg-red-600/30 border-red-600/50',
                'blue': 'bg-blue-600/30 border-blue-600/50',
                'green': 'bg-green-600/30 border-green-600/50',
                'purple': 'bg-purple-600/30 border-purple-600/50',
                'yellow': 'bg-yellow-600/30 border-yellow-600/50',
                'orange': 'bg-orange-600/30 border-orange-600/50'
            };
            
            const bgClass = colorClasses[tool.color] || 'bg-gray-600/30 border-gray-600/50';
            
            return `
                <div class="tool-card glass-effect rounded-xl p-6">
                    <div class="flex items-start justify-between mb-4">
                        <div class="flex items-center">
                            <i class="fas ${tool.icon} text-2xl mr-3 text-${tool.color}-400"></i>
                            <div>
                                <h4 class="text-xl font-semibold">${tool.name}</h4>
                                <p class="text-sm text-gray-400">${tool.category}</p>
                            </div>
                        </div>
                    </div>
                    
                    <p class="text-gray-300 mb-4">${tool.description}</p>
                    
                    <div class="mb-4">
                        <h5 class="font-semibold mb-2 text-sm">
                            <i class="fas fa-bullseye mr-1 text-green-400"></i>Kullanım Alanları
                        </h5>
                        <div class="flex flex-wrap gap-2">
                            ${tool.useCases.slice(0, 3).map(use => `
                                <span class="${bgClass} px-2 py-1 rounded text-xs border">
                                    ${use}
                                </span>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <h5 class="font-semibold mb-2 text-sm">
                            <i class="fas fa-terminal mr-1 text-blue-400"></i>Örnek Komut
                        </h5>
                        <div class="terminal-style rounded p-2 text-xs overflow-x-auto">
                            <code>${tool.commands[0]}</code>
                        </div>
                    </div>
                    
                    <button onclick="showToolDetails('${tool.name}')" class="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 py-2 rounded-lg text-sm transition">
                        <i class="fas fa-info-circle mr-2"></i>Detaylı Bilgi
                    </button>
                </div>
            `;
        }

        function filterByNeed(need) {
            // Filter logic based on need
            const filterMap = {
                'email': ['THEHARVESTER'],
                'subdomain': ['AMASS', 'SUBFINDER'],
                'person': ['SHERLOCK', 'PHONEINFOGA'],
                'leak': ['HAVEIBEENPWNED']
            };
            
            const grid = document.getElementById('tools-grid');
            grid.innerHTML = '';
            
            const relevantTools = filterMap[need] || [];
            
            Object.keys(osintTools).forEach(key => {
                if (need === 'all' || relevantTools.includes(key)) {
                    grid.innerHTML += createToolCard(osintTools[key]);
                }
            });
            
            if (grid.innerHTML === '') {
                grid.innerHTML = '<p class="col-span-3 text-center text-gray-400">Bu kategori için araç bulunamadı.</p>';
            }
        }

        function showScenarios() {
            const section = document.getElementById('scenarios-section');
            section.classList.toggle('hidden');
            
            if (!section.classList.contains('hidden')) {
                loadScenarios();
            }
        }

        function loadScenarios() {
            const content = document.getElementById('scenarios-content');
            content.innerHTML = `
                <div class="space-y-6">
                    <!-- Company Recon -->
                    <div class="bg-white/5 rounded-lg p-6">
                        <h4 class="text-xl font-semibold mb-4 text-blue-400">
                            <i class="fas fa-building mr-2"></i>Şirket Reconnaissance
                        </h4>
                        <div class="space-y-3">
                            <div class="flex items-start">
                                <span class="bg-blue-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm mr-3">1</span>
                                <div class="flex-1">
                                    <p class="font-medium">Subdomain Keşfi</p>
                                    <code class="text-xs text-green-400">amass enum -d company.com</code>
                                </div>
                            </div>
                            <div class="flex items-start">
                                <span class="bg-blue-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm mr-3">2</span>
                                <div class="flex-1">
                                    <p class="font-medium">Email Toplama</p>
                                    <code class="text-xs text-green-400">theHarvester -d company.com -b all</code>
                                </div>
                            </div>
                            <div class="flex items-start">
                                <span class="bg-blue-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm mr-3">3</span>
                                <div class="flex-1">
                                    <p class="font-medium">Exposed Devices</p>
                                    <code class="text-xs text-green-400">shodan search hostname:company.com</code>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Person Investigation -->
                    <div class="bg-white/5 rounded-lg p-6">
                        <h4 class="text-xl font-semibold mb-4 text-green-400">
                            <i class="fas fa-user mr-2"></i>Kişi Araştırması
                        </h4>
                        <div class="space-y-3">
                            <div class="flex items-start">
                                <span class="bg-green-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm mr-3">1</span>
                                <div class="flex-1">
                                    <p class="font-medium">Username Search</p>
                                    <code class="text-xs text-green-400">sherlock username123</code>
                                </div>
                            </div>
                            <div class="flex items-start">
                                <span class="bg-green-600 text-white rounded-full w-6 h-6 flex items-center justify-center text-sm mr-3">2</span>
                                <div class="flex-1">
                                    <p class="font-medium">Phone Lookup</p>
                                    <code class="text-xs text-green-400">phoneinfoga scan -n +90...</code>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        function showToolDetails(toolName) {
            alert(`${toolName} için detaylı bilgi ve tüm komutlar gösterilecek.\\n\\nBu özellik yakında eklenecek!`);
        }

        function showQuickStart() {
            alert('Hızlı başlangıç rehberi hazırlanıyor...\\n\\n1. API Key\'leri edinin\\n2. Araçları kurun\\n3. Senaryoları takip edin');
        }
    </script>
</body>
</html>
'''

@router.get("/")
async def osint_dashboard():
    """OSINT araçları dashboard"""
    return HTMLResponse(content=OSINT_HTML)

@router.post("/api/recommend")
async def recommend_tools(data: Dict):
    """Hedefe göre OSINT araç önerisi"""
    objective = data.get("objective", "")
    recommendations = osint_framework.recommend_tools(objective)
    
    return {
        "objective": objective,
        "recommended_tools": recommendations,
        "count": len(recommendations)
    }

@router.post("/api/generate-plan")
async def generate_recon_plan(data: Dict):
    """Reconnaissance planı oluştur"""
    target_type = data.get("target_type", "domain")
    target = data.get("target", "")
    
    plan = osint_framework.generate_recon_plan(target_type, target)
    return plan

@router.get("/api/scenarios")
async def get_scenarios():
    """Tüm OSINT senaryolarını getir"""
    return osint_framework.scenarios

@router.get("/api/tools/{category}")
async def get_tools_by_category(category: str):
    """Kategoriye göre araçları getir"""
    tools = osint_framework.get_tools_by_category(category)
    return {
        "category": category,
        "tools": [
            {
                "name": tool.name,
                "description": tool.description,
                "use_cases": tool.use_cases,
                "commands": tool.example_commands[:3]
            }
            for tool in tools
        ]
    }