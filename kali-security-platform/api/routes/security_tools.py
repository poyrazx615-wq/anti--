# Security Tools Web Interface
from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from typing import Dict, List, Optional, Any
from modules.security_tools import tools_manager as SecurityToolsManager
import subprocess
import asyncio
import json
import sqlite3
from datetime import datetime
import uuid
import os

router = APIRouter()
tools_manager = SecurityToolsManager

# Initialize database
def init_database():
    """Initialize SQLite database for storing results"""
    conn = sqlite3.connect('security_tools.db')
    cursor = conn.cursor()
    
    # Projects table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            target TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            project_id TEXT,
            tool_name TEXT NOT NULL,
            command TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            output TEXT,
            error TEXT,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects (id)
        )
    ''')
    
    # Tool results table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tool_results (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            result_type TEXT,
            data JSON,
            severity TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on module load
init_database()

# Security Tools Dashboard HTML
SECURITY_TOOLS_HTML = '''
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Tools Platform - Complete Toolkit</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-bash.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        body { font-family: 'Inter', sans-serif; }
        
        :root {
            --bg-dark: #0f1419;
            --bg-light: #ffffff;
            --text-dark: #ffffff;
            --text-light: #000000;
        }
        
        .dark-mode {
            background: var(--bg-dark);
            color: var(--text-dark);
        }
        
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
            cursor: pointer;
        }
        
        .tool-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }
        
        .terminal {
            background: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Consolas', 'Monaco', monospace;
            border-radius: 8px;
            padding: 20px;
            min-height: 400px;
            max-height: 600px;
            overflow-y: auto;
        }
        
        .terminal-line {
            margin: 5px 0;
            font-size: 14px;
            line-height: 1.5;
        }
        
        .terminal-prompt {
            color: #4ec9b0;
        }
        
        .terminal-output {
            color: #d4d4d4;
        }
        
        .terminal-error {
            color: #f48771;
        }
        
        .terminal-success {
            color: #4ec9b0;
        }
        
        .category-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .loading-spinner {
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top: 3px solid #667eea;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .workflow-step {
            position: relative;
            padding-left: 40px;
            margin-bottom: 20px;
        }
        
        .workflow-step::before {
            content: '';
            position: absolute;
            left: 15px;
            top: 30px;
            bottom: -20px;
            width: 2px;
            background: linear-gradient(to bottom, #667eea, #764ba2);
        }
        
        .workflow-step:last-child::before {
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
                    <i class="fas fa-shield-alt text-3xl text-purple-400"></i>
                    <h1 class="text-2xl font-bold">Security Tools Platform</h1>
                    <span class="bg-red-600 px-2 py-1 rounded text-xs">100+ Tools</span>
                </div>
                <div class="flex items-center space-x-6">
                    <button onclick="toggleDarkMode()" class="hover:text-purple-300">
                        <i class="fas fa-moon"></i>
                    </button>
                    <a href="/" class="hover:text-purple-300">Dashboard</a>
                    <a href="/security-tools" class="text-purple-300">Tools</a>
                    <a href="/osint" class="hover:text-purple-300">OSINT</a>
                    <a href="/exploit-advisor" class="hover:text-purple-300">Exploits</a>
                    <a href="/reports" class="hover:text-purple-300">Reports</a>
                </div>
            </div>
        </div>
    </nav>

    <div class="container mx-auto px-6 py-8">
        <!-- Header Section -->
        <div class="glass-effect rounded-xl p-6 mb-8">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-3xl font-bold">
                    <i class="fas fa-toolbox mr-3 text-yellow-400"></i>
                    Complete Security Testing Toolkit
                </h2>
                <div class="flex space-x-3">
                    <button onclick="showWorkflow()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg">
                        <i class="fas fa-project-diagram mr-2"></i>Workflows
                    </button>
                    <button onclick="showCheatsheet()" class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded-lg">
                        <i class="fas fa-book mr-2"></i>Cheatsheet
                    </button>
                    <button onclick="exportReport()" class="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded-lg">
                        <i class="fas fa-file-pdf mr-2"></i>Export PDF
                    </button>
                </div>
            </div>
            
            <!-- Search and Filter Bar -->
            <div class="flex space-x-4">
                <div class="flex-1">
                    <input type="text" id="tool-search" placeholder="Search tools..." 
                           class="w-full px-4 py-2 rounded-lg bg-white/10 border border-white/20 focus:outline-none focus:border-purple-400"
                           onkeyup="searchTools()">
                </div>
                <select id="category-filter" onchange="filterByCategory()" 
                        class="px-4 py-2 rounded-lg bg-white/10 border border-white/20">
                    <option value="all">All Categories</option>
                    <option value="Web Scanner">Web Scanner</option>
                    <option value="Fuzzer">Fuzzer</option>
                    <option value="Exploitation">Exploitation</option>
                    <option value="Network Exploitation">Network</option>
                    <option value="Privilege Escalation">Privesc</option>
                    <option value="Password Cracking">Passwords</option>
                    <option value="Wireless">Wireless</option>
                    <option value="Cloud Security">Cloud</option>
                    <option value="Mobile Security">Mobile</option>
                    <option value="Pivoting">Pivoting</option>
                    <option value="Post-Exploitation">Post-Exploit</option>
                </select>
                <select id="platform-filter" onchange="filterByPlatform()" 
                        class="px-4 py-2 rounded-lg bg-white/10 border border-white/20">
                    <option value="all">All Platforms</option>
                    <option value="linux">Linux</option>
                    <option value="windows">Windows</option>
                    <option value="macos">macOS</option>
                </select>
            </div>
        </div>

        <!-- Statistics Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div class="glass-effect rounded-lg p-4 text-center">
                <i class="fas fa-tools text-3xl text-blue-400 mb-2"></i>
                <p class="text-2xl font-bold" id="total-tools">100+</p>
                <p class="text-sm text-gray-300">Total Tools</p>
            </div>
            <div class="glass-effect rounded-lg p-4 text-center">
                <i class="fas fa-layer-group text-3xl text-green-400 mb-2"></i>
                <p class="text-2xl font-bold" id="total-categories">15</p>
                <p class="text-sm text-gray-300">Categories</p>
            </div>
            <div class="glass-effect rounded-lg p-4 text-center">
                <i class="fas fa-play-circle text-3xl text-yellow-400 mb-2"></i>
                <p class="text-2xl font-bold" id="active-scans">0</p>
                <p class="text-sm text-gray-300">Active Scans</p>
            </div>
            <div class="glass-effect rounded-lg p-4 text-center">
                <i class="fas fa-history text-3xl text-purple-400 mb-2"></i>
                <p class="text-2xl font-bold" id="completed-scans">0</p>
                <p class="text-sm text-gray-300">Completed</p>
            </div>
        </div>

        <!-- Main Content Area -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- Tools List (Left Column) -->
            <div class="lg:col-span-1">
                <div class="glass-effect rounded-xl p-6 max-h-screen overflow-y-auto">
                    <h3 class="text-xl font-semibold mb-4">
                        <i class="fas fa-list mr-2 text-blue-400"></i>
                        Available Tools
                    </h3>
                    <div id="tools-list" class="space-y-3">
                        <!-- Tools will be loaded here -->
                        <div class="text-center py-8">
                            <div class="loading-spinner mx-auto mb-4"></div>
                            <p>Loading tools...</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tool Details and Execution (Right Column) -->
            <div class="lg:col-span-2">
                <!-- Tool Details -->
                <div class="glass-effect rounded-xl p-6 mb-6">
                    <div id="tool-details">
                        <div class="text-center py-12 text-gray-400">
                            <i class="fas fa-mouse-pointer text-6xl mb-4"></i>
                            <p>Select a tool to view details and execute commands</p>
                        </div>
                    </div>
                </div>

                <!-- Command Execution Terminal -->
                <div class="glass-effect rounded-xl p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-xl font-semibold">
                            <i class="fas fa-terminal mr-2 text-green-400"></i>
                            Command Execution
                        </h3>
                        <div class="flex space-x-2">
                            <button onclick="clearTerminal()" class="px-3 py-1 bg-gray-600 hover:bg-gray-700 rounded text-sm">
                                <i class="fas fa-trash mr-1"></i>Clear
                            </button>
                            <button onclick="saveOutput()" class="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-sm">
                                <i class="fas fa-save mr-1"></i>Save
                            </button>
                        </div>
                    </div>
                    
                    <div class="mb-4">
                        <div class="flex space-x-2">
                            <input type="text" id="command-input" 
                                   placeholder="Enter command or select from examples..." 
                                   class="flex-1 px-4 py-2 rounded-lg bg-white/10 border border-white/20 focus:outline-none focus:border-green-400"
                                   onkeypress="handleCommandInput(event)">
                            <button onclick="executeCommand()" class="px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg">
                                <i class="fas fa-play mr-2"></i>Execute
                            </button>
                        </div>
                    </div>
                    
                    <div id="terminal-output" class="terminal">
                        <div class="terminal-line">
                            <span class="terminal-prompt">$</span>
                            <span class="terminal-output">Welcome to Security Tools Platform Terminal</span>
                        </div>
                        <div class="terminal-line">
                            <span class="terminal-output">Type 'help' for available commands</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Workflow Modal -->
        <div id="workflow-modal" class="fixed inset-0 bg-black/50 hidden z-50 flex items-center justify-center p-4">
            <div class="bg-gray-900 rounded-xl p-8 max-w-4xl max-h-screen overflow-y-auto">
                <div class="flex justify-between items-center mb-6">
                    <h3 class="text-2xl font-bold">Penetration Testing Workflows</h3>
                    <button onclick="closeWorkflow()" class="text-gray-400 hover:text-white">
                        <i class="fas fa-times text-2xl"></i>
                    </button>
                </div>
                <div id="workflow-content">
                    <!-- Workflow content will be loaded here -->
                </div>
            </div>
        </div>
    </div>

    <script>
        // Global variables
        let allTools = [];
        let currentTool = null;
        let commandHistory = [];
        let historyIndex = -1;
        let activeScans = new Map();
        let completedScans = 0;

        // Load tools on page load
        document.addEventListener('DOMContentLoaded', () => {
            loadTools();
            loadStatistics();
            setupKeyboardShortcuts();
            setupAutoComplete();
        });

        // Load all tools
        async function loadTools() {
            try {
                const response = await fetch('/api/security-tools/list');
                const data = await response.json();
                allTools = data.tools;
                displayTools(allTools);
                updateStatistics(data.statistics);
            } catch (error) {
                console.error('Error loading tools:', error);
                showNotification('Failed to load tools', 'error');
            }
        }

        // Display tools in the list
        function displayTools(tools) {
            const toolsList = document.getElementById('tools-list');
            toolsList.innerHTML = '';
            
            if (tools.length === 0) {
                toolsList.innerHTML = '<p class="text-center text-gray-400">No tools found</p>';
                return;
            }
            
            tools.forEach(tool => {
                const categoryColor = getCategoryColor(tool.category);
                const toolCard = `
                    <div class="tool-card bg-white/5 rounded-lg p-4 hover:bg-white/10" 
                         onclick="selectTool('${tool.name}')">
                        <div class="flex items-start justify-between mb-2">
                            <h4 class="font-semibold">${tool.name}</h4>
                            <span class="category-badge bg-${categoryColor}-600/30 text-${categoryColor}-400">
                                ${tool.category}
                            </span>
                        </div>
                        <p class="text-sm text-gray-300 mb-2">${tool.description}</p>
                        <div class="flex items-center justify-between text-xs">
                            <div class="flex space-x-3">
                                ${tool.gui_available ? '<i class="fas fa-desktop text-blue-400" title="GUI Available"></i>' : ''}
                                ${tool.api_support ? '<i class="fas fa-plug text-green-400" title="API Support"></i>' : ''}
                                ${tool.requires_root ? '<i class="fas fa-user-shield text-red-400" title="Requires Root"></i>' : ''}
                            </div>
                            <div class="text-gray-400">
                                ${tool.platform.join(', ')}
                            </div>
                        </div>
                    </div>
                `;
                toolsList.innerHTML += toolCard;
            });
        }

        // Select and display tool details
        async function selectTool(toolName) {
            try {
                const response = await fetch(`/api/security-tools/tool/${toolName}`);
                const tool = await response.json();
                currentTool = tool;
                displayToolDetails(tool);
            } catch (error) {
                console.error('Error loading tool details:', error);
            }
        }

        // Display tool details
        function displayToolDetails(tool) {
            const detailsDiv = document.getElementById('tool-details');
            
            const detailsHTML = `
                <div>
                    <div class="flex items-start justify-between mb-4">
                        <div>
                            <h3 class="text-2xl font-bold mb-2">${tool.name}</h3>
                            <p class="text-gray-300">${tool.description}</p>
                        </div>
                        <div class="flex space-x-2">
                            <a href="${tool.github}" target="_blank" class="text-gray-400 hover:text-white">
                                <i class="fab fa-github text-2xl"></i>
                            </a>
                            <a href="${tool.documentation}" target="_blank" class="text-gray-400 hover:text-white">
                                <i class="fas fa-book text-2xl"></i>
                            </a>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-2 gap-4 mb-6">
                        <div>
                            <h4 class="font-semibold mb-2">
                                <i class="fas fa-download mr-2 text-blue-400"></i>Installation
                            </h4>
                            <div class="bg-black/30 rounded p-3">
                                <code class="text-sm">${tool.installation.linux || tool.installation.apt || 'N/A'}</code>
                                <button onclick="copyToClipboard('${tool.installation.linux}')" class="ml-2 text-gray-400 hover:text-white">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </div>
                        </div>
                        
                        <div>
                            <h4 class="font-semibold mb-2">
                                <i class="fas fa-info-circle mr-2 text-green-400"></i>Information
                            </h4>
                            <div class="text-sm space-y-1">
                                <p>Category: ${tool.category}</p>
                                <p>Subcategory: ${tool.subcategory}</p>
                                <p>Platforms: ${tool.platform.join(', ')}</p>
                                <p>Output: ${tool.output_format}</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-6">
                        <h4 class="font-semibold mb-3">
                            <i class="fas fa-terminal mr-2 text-yellow-400"></i>Example Commands
                        </h4>
                        <div class="space-y-3">
                            ${tool.examples.map(example => `
                                <div class="bg-black/30 rounded p-3">
                                    <p class="text-sm text-gray-400 mb-1">${example.description}</p>
                                    <div class="flex items-center justify-between">
                                        <code class="text-sm flex-1">${example.command}</code>
                                        <div class="flex space-x-2 ml-4">
                                            <button onclick="copyToClipboard('${example.command}')" class="text-gray-400 hover:text-white">
                                                <i class="fas fa-copy"></i>
                                            </button>
                                            <button onclick="setCommand('${example.command}')" class="text-gray-400 hover:text-white">
                                                <i class="fas fa-terminal"></i>
                                            </button>
                                            <button onclick="executeDirectly('${example.command}')" class="text-gray-400 hover:text-white">
                                                <i class="fas fa-play"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <h4 class="font-semibold mb-2">
                                <i class="fas fa-flag mr-2 text-purple-400"></i>Options
                            </h4>
                            <div class="bg-black/30 rounded p-3 max-h-40 overflow-y-auto">
                                ${tool.options.map(opt => `
                                    <div class="text-sm mb-1">
                                        <code class="text-green-400">${opt.flag}</code>
                                        <span class="text-gray-400 ml-2">${opt.description}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                        
                        <div>
                            <h4 class="font-semibold mb-2">
                                <i class="fas fa-exchange-alt mr-2 text-orange-400"></i>Alternatives
                            </h4>
                            <div class="flex flex-wrap gap-2">
                                ${tool.alternatives.map(alt => `
                                    <span class="bg-orange-600/30 px-3 py-1 rounded text-sm cursor-pointer hover:bg-orange-600/50"
                                          onclick="selectTool('${alt}')">
                                        ${alt}
                                    </span>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            `;
            
            detailsDiv.innerHTML = detailsHTML;
        }

        // Execute command
        async function executeCommand() {
            const commandInput = document.getElementById('command-input');
            const command = commandInput.value.trim();
            
            if (!command) return;
            
            // Add to history
            commandHistory.push(command);
            historyIndex = commandHistory.length;
            
            // Display command in terminal
            addTerminalLine(`$ ${command}`, 'terminal-prompt');
            
            // Clear input
            commandInput.value = '';
            
            // Create scan ID
            const scanId = generateId();
            activeScans.set(scanId, command);
            updateActiveScans();
            
            try {
                // Execute command via API
                const response = await fetch('/api/security-tools/execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        command: command,
                        tool: currentTool?.name || 'unknown',
                        scan_id: scanId
                    })
                });
                
                if (response.ok) {
                    // Stream output
                    const reader = response.body.getReader();
                    const decoder = new TextDecoder();
                    
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        
                        const chunk = decoder.decode(value);
                        addTerminalLine(chunk, 'terminal-output');
                    }
                    
                    addTerminalLine('Command completed successfully', 'terminal-success');
                } else {
                    const error = await response.text();
                    addTerminalLine(`Error: ${error}`, 'terminal-error');
                }
            } catch (error) {
                addTerminalLine(`Error: ${error.message}`, 'terminal-error');
            } finally {
                // Remove from active scans
                activeScans.delete(scanId);
                completedScans++;
                updateActiveScans();
                updateCompletedScans();
            }
        }

        // Add line to terminal
        function addTerminalLine(text, className = 'terminal-output') {
            const terminal = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.className = 'terminal-line';
            line.innerHTML = `<span class="${className}">${escapeHtml(text)}</span>`;
            terminal.appendChild(line);
            terminal.scrollTop = terminal.scrollHeight;
        }

        // Clear terminal
        function clearTerminal() {
            const terminal = document.getElementById('terminal-output');
            terminal.innerHTML = `
                <div class="terminal-line">
                    <span class="terminal-prompt">$</span>
                    <span class="terminal-output">Terminal cleared</span>
                </div>
            `;
        }

        // Save terminal output
        async function saveOutput() {
            const terminal = document.getElementById('terminal-output');
            const content = terminal.innerText;
            
            try {
                const response = await fetch('/api/security-tools/save-output', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        content: content,
                        tool: currentTool?.name || 'unknown',
                        timestamp: new Date().toISOString()
                    })
                });
                
                if (response.ok) {
                    const result = await response.json();
                    showNotification(`Output saved: ${result.filename}`, 'success');
                }
            } catch (error) {
                showNotification('Failed to save output', 'error');
            }
        }

        // Search tools
        function searchTools() {
            const searchTerm = document.getElementById('tool-search').value.toLowerCase();
            const filtered = allTools.filter(tool => 
                tool.name.toLowerCase().includes(searchTerm) ||
                tool.description.toLowerCase().includes(searchTerm) ||
                tool.category.toLowerCase().includes(searchTerm)
            );
            displayTools(filtered);
        }

        // Filter by category
        function filterByCategory() {
            const category = document.getElementById('category-filter').value;
            if (category === 'all') {
                displayTools(allTools);
            } else {
                const filtered = allTools.filter(tool => tool.category === category);
                displayTools(filtered);
            }
        }

        // Filter by platform
        function filterByPlatform() {
            const platform = document.getElementById('platform-filter').value;
            if (platform === 'all') {
                displayTools(allTools);
            } else {
                const filtered = allTools.filter(tool => tool.platform.includes(platform));
                displayTools(filtered);
            }
        }

        // Show workflow modal
        async function showWorkflow() {
            const modal = document.getElementById('workflow-modal');
            modal.classList.remove('hidden');
            
            try {
                const response = await fetch('/api/security-tools/workflows');
                const workflows = await response.json();
                displayWorkflows(workflows);
            } catch (error) {
                console.error('Error loading workflows:', error);
            }
        }

        // Display workflows
        function displayWorkflows(workflows) {
            const content = document.getElementById('workflow-content');
            
            let html = '<div class="space-y-6">';
            
            for (const [type, workflow] of Object.entries(workflows)) {
                html += `
                    <div class="bg-white/10 rounded-lg p-6">
                        <h4 class="text-xl font-semibold mb-4 capitalize">${type.replace(/_/g, ' ')}</h4>
                        <div class="space-y-4">
                            ${Object.entries(workflow).map(([phase, tools]) => `
                                <div class="workflow-step">
                                    <div class="step-number">${phase.split('_')[0]}</div>
                                    <div class="ml-2">
                                        <h5 class="font-semibold mb-2">${phase.split('_').slice(1).join(' ').toUpperCase()}</h5>
                                        <div class="flex flex-wrap gap-2">
                                            ${tools.map(tool => `
                                                <span class="bg-blue-600/30 px-3 py-1 rounded text-sm cursor-pointer hover:bg-blue-600/50"
                                                      onclick="selectTool('${tool}')">
                                                    ${tool}
                                                </span>
                                            `).join('')}
                                        </div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
            
            html += '</div>';
            content.innerHTML = html;
        }

        // Close workflow modal
        function closeWorkflow() {
            document.getElementById('workflow-modal').classList.add('hidden');
        }

        // Show cheatsheet
        async function showCheatsheet() {
            try {
                const response = await fetch('/api/security-tools/cheatsheet');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                window.open(url, '_blank');
            } catch (error) {
                showNotification('Failed to generate cheatsheet', 'error');
            }
        }

        // Export PDF report
        async function exportReport() {
            try {
                const response = await fetch('/api/security-tools/export-pdf');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `security-tools-report-${Date.now()}.pdf`;
                a.click();
                showNotification('Report exported successfully', 'success');
            } catch (error) {
                showNotification('Failed to export report', 'error');
            }
        }

        // Utility functions
        function getCategoryColor(category) {
            const colors = {
                'Web Scanner': 'blue',
                'Fuzzer': 'green',
                'Exploitation': 'red',
                'Network Exploitation': 'purple',
                'Privilege Escalation': 'yellow',
                'Password Cracking': 'orange',
                'Wireless': 'pink',
                'Cloud Security': 'indigo',
                'Mobile Security': 'teal',
                'Pivoting': 'gray'
            };
            return colors[category] || 'gray';
        }

        function generateId() {
            return 'scan-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showNotification('Copied to clipboard', 'success');
            });
        }

        function setCommand(command) {
            document.getElementById('command-input').value = command;
        }

        function executeDirectly(command) {
            setCommand(command);
            executeCommand();
        }

        function showNotification(message, type = 'info') {
            // Simple notification implementation
            const notification = document.createElement('div');
            notification.className = `fixed top-4 right-4 px-6 py-3 rounded-lg text-white z-50 ${
                type === 'success' ? 'bg-green-600' : 
                type === 'error' ? 'bg-red-600' : 'bg-blue-600'
            }`;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.remove();
            }, 3000);
        }

        function updateActiveScans() {
            document.getElementById('active-scans').textContent = activeScans.size;
        }

        function updateCompletedScans() {
            document.getElementById('completed-scans').textContent = completedScans;
        }

        function updateStatistics(stats) {
            document.getElementById('total-tools').textContent = stats.total_tools;
            document.getElementById('total-categories').textContent = Object.keys(stats.categories).length;
        }

        function loadStatistics() {
            // Load saved statistics from localStorage or API
            const saved = localStorage.getItem('scan-statistics');
            if (saved) {
                const stats = JSON.parse(saved);
                completedScans = stats.completed || 0;
                updateCompletedScans();
            }
        }

        function toggleDarkMode() {
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        }

        function setupKeyboardShortcuts() {
            document.addEventListener('keydown', (e) => {
                // Ctrl+K for search
                if (e.ctrlKey && e.key === 'k') {
                    e.preventDefault();
                    document.getElementById('tool-search').focus();
                }
                
                // Ctrl+Enter to execute
                if (e.ctrlKey && e.key === 'Enter') {
                    executeCommand();
                }
                
                // Ctrl+L to clear terminal
                if (e.ctrlKey && e.key === 'l') {
                    e.preventDefault();
                    clearTerminal();
                }
            });
        }

        function setupAutoComplete() {
            const commandInput = document.getElementById('command-input');
            
            commandInput.addEventListener('keydown', (e) => {
                // Arrow up/down for history
                if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    if (historyIndex > 0) {
                        historyIndex--;
                        commandInput.value = commandHistory[historyIndex];
                    }
                } else if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    if (historyIndex < commandHistory.length - 1) {
                        historyIndex++;
                        commandInput.value = commandHistory[historyIndex];
                    } else {
                        historyIndex = commandHistory.length;
                        commandInput.value = '';
                    }
                }
            });
        }

        function handleCommandInput(event) {
            if (event.key === 'Enter') {
                executeCommand();
            }
        }

        // Initialize dark mode from localStorage
        if (localStorage.getItem('darkMode') === 'true') {
            document.body.classList.add('dark-mode');
        }
    </script>
</body>
</html>
'''

@router.get("/")
async def security_tools_page():
    """Security tools dashboard page"""
    return HTMLResponse(content=SECURITY_TOOLS_HTML)

@router.get("/api/list")
async def list_tools():
    """List all available security tools"""
    tools = []
    for name, tool in tools_manager.all_tools.items():
        tools.append({
            "name": tool.name,
            "category": tool.category,
            "subcategory": tool.subcategory,
            "description": tool.description,
            "platform": tool.platform,
            "requires_root": tool.requires_root,
            "gui_available": tool.gui_available,
            "api_support": tool.api_support
        })
    
    return {
        "tools": tools,
        "statistics": tools_manager.get_statistics()
    }

@router.get("/api/tool/{tool_name}")
async def get_tool_details(tool_name: str):
    """Get detailed information about a specific tool"""
    tool = tools_manager.get_tool(tool_name)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    
    return {
        "name": tool.name,
        "category": tool.category,
        "subcategory": tool.subcategory,
        "description": tool.description,
        "installation": tool.installation,
        "usage": tool.usage,
        "examples": tool.examples,
        "options": tool.options,
        "output_format": tool.output_format,
        "requires_root": tool.requires_root,
        "gui_available": tool.gui_available,
        "api_support": tool.api_support,
        "platform": tool.platform,
        "dependencies": tool.dependencies,
        "documentation": tool.documentation,
        "github": tool.github,
        "alternatives": tool.alternatives
    }

@router.post("/api/execute")
async def execute_tool_command(data: Dict):
    """Execute a security tool command"""
    command = data.get("command", "")
    tool_name = data.get("tool", "")
    scan_id = data.get("scan_id", str(uuid.uuid4()))
    
    # Security check - only allow whitelisted commands
    if not is_safe_command(command):
        raise HTTPException(status_code=400, detail="Command not allowed")
    
    # Additional security: Split command to prevent injection
    import shlex
    try:
        safe_command_args = shlex.split(command)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid command format")
    
    # Save scan to database
    conn = sqlite3.connect('security_tools.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scans (id, tool_name, command, status, started_at)
        VALUES (?, ?, ?, 'running', ?)
    ''', (scan_id, tool_name, command, datetime.now()))
    conn.commit()
    
    try:
        # Execute command asynchronously
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Stream output
        async def stream_output():
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                yield line.decode()
        
        return StreamingResponse(stream_output(), media_type="text/plain")
        
    except Exception as e:
        # Update scan status
        cursor.execute('''
            UPDATE scans SET status = 'failed', error = ?, completed_at = ?
            WHERE id = ?
        ''', (str(e), datetime.now(), scan_id))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Update scan status
        cursor.execute('''
            UPDATE scans SET status = 'completed', completed_at = ?
            WHERE id = ?
        ''', (datetime.now(), scan_id))
        conn.commit()
        conn.close()

@router.get("/api/workflows")
async def get_workflows():
    """Get penetration testing workflows"""
    workflows = tools_manager.create_pentest_workflow("web_application")
    workflows.update(tools_manager.create_pentest_workflow("network"))
    workflows.update(tools_manager.create_pentest_workflow("active_directory"))
    workflows.update(tools_manager.create_pentest_workflow("wireless"))
    workflows.update(tools_manager.create_pentest_workflow("mobile"))
    workflows.update(tools_manager.create_pentest_workflow("cloud"))
    
    return workflows

@router.get("/api/cheatsheet")
async def generate_cheatsheet_pdf():
    """Generate PDF cheatsheet for all tools"""
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    import io
    
    # Create PDF buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph("Security Tools Cheatsheet", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    # Add tools by category
    for category, tool_names in tools_manager.categories.items():
        # Category header
        category_title = Paragraph(f"<b>{category}</b>", styles['Heading2'])
        elements.append(category_title)
        elements.append(Spacer(1, 6))
        
        # Tools in category
        for tool_name in tool_names[:5]:  # Limit to 5 tools per category for PDF size
            tool = tools_manager.get_tool(tool_name)
            if tool:
                tool_para = Paragraph(f"<b>{tool.name}</b>: {tool.description[:100]}...", styles['BodyText'])
                elements.append(tool_para)
                
                # Add first example command
                if tool.examples:
                    cmd_para = Paragraph(f"<font name='Courier' size='9'>{tool.examples[0]['command'][:80]}...</font>", styles['Code'])
                    elements.append(cmd_para)
                
                elements.append(Spacer(1, 6))
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    
    return StreamingResponse(buffer, media_type="application/pdf", 
                           headers={"Content-Disposition": "attachment; filename=security-tools-cheatsheet.pdf"})

@router.get("/api/export-pdf")
async def export_pdf_report():
    """Export comprehensive PDF report"""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    import io
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph("Security Tools Platform - Comprehensive Report", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    
    # Date
    date = Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(date)
    elements.append(Spacer(1, 12))
    
    # Statistics
    stats = tools_manager.get_statistics()
    stats_para = Paragraph(f"<b>Total Tools:</b> {stats['total_tools']}<br/>"
                          f"<b>Categories:</b> {len(stats['categories'])}<br/>"
                          f"<b>Tools with GUI:</b> {stats['has_gui']}<br/>"
                          f"<b>Tools with API:</b> {stats['has_api']}", styles['BodyText'])
    elements.append(stats_para)
    elements.append(Spacer(1, 12))
    
    # Recent scans from database
    conn = sqlite3.connect('security_tools.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT tool_name, command, status, started_at 
        FROM scans 
        ORDER BY started_at DESC 
        LIMIT 10
    ''')
    scans = cursor.fetchall()
    conn.close()
    
    if scans:
        scan_data = [['Tool', 'Command', 'Status', 'Time']]
        for scan in scans:
            scan_data.append([scan[0], scan[1][:30] + '...', scan[2], scan[3]])
        
        scan_table = Table(scan_data)
        scan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(scan_table)
    
    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    
    return StreamingResponse(buffer, media_type="application/pdf",
                           headers={"Content-Disposition": f"attachment; filename=security-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"})

@router.post("/api/save-output")
async def save_terminal_output(data: Dict):
    """Save terminal output to file"""
    content = data.get("content", "")
    tool = data.get("tool", "unknown")
    timestamp = data.get("timestamp", datetime.now().isoformat())
    
    # Create outputs directory if not exists
    os.makedirs("outputs", exist_ok=True)
    
    # Generate filename
    filename = f"outputs/{tool}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    # Save to file
    with open(filename, 'w') as f:
        f.write(f"Tool: {tool}\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write("=" * 80 + "\n")
        f.write(content)
    
    return {"filename": filename, "status": "saved"}

def is_safe_command(command: str) -> bool:
    """Check if command is safe to execute"""
    # This is a basic safety check - enhance based on needs
    dangerous_patterns = [
        'rm -rf /',
        'format c:',
        ':(){ :|:& };:',  # Fork bomb
        'dd if=/dev/zero',
        'mkfs',
        '> /dev/sda'
    ]
    
    command_lower = command.lower()
    for pattern in dangerous_patterns:
        if pattern.lower() in command_lower:
            return False
    
    return True