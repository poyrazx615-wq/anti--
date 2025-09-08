#!/bin/bash

# Kali Security Platform - Installation Script

echo "
╔══════════════════════════════════════════════════════════════╗
║     KALI SECURITY PLATFORM - INSTALLATION                   ║
╚══════════════════════════════════════════════════════════════╝
"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_warning "This script is running as root. Some tools will be installed system-wide."
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    DISTRO=$(lsb_release -si 2>/dev/null || echo "Unknown")
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported OS: $OSTYPE"
    exit 1
fi

print_status "Detected OS: $OS ($DISTRO)"

# Update package manager
print_status "Updating package manager..."
if [[ "$OS" == "linux" ]]; then
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
    elif command -v yum &> /dev/null; then
        sudo yum update -y
    elif command -v pacman &> /dev/null; then
        sudo pacman -Syu --noconfirm
    fi
elif [[ "$OS" == "macos" ]]; then
    if ! command -v brew &> /dev/null; then
        print_status "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew update
fi

# Install Python 3.11+
print_status "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_status "Installing Python 3..."
    if [[ "$OS" == "linux" ]]; then
        sudo apt-get install -y python3 python3-pip python3-venv
    elif [[ "$OS" == "macos" ]]; then
        brew install python@3.11
    fi
else
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    print_status "Python $PYTHON_VERSION detected"
fi

# Install Docker
print_status "Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    print_warning "Docker not found. Would you like to install it? (y/n)"
    read -r response
    if [[ "$response" == "y" ]]; then
        if [[ "$OS" == "linux" ]]; then
            curl -fsSL https://get.docker.com -o get-docker.sh
            sudo sh get-docker.sh
            sudo usermod -aG docker $USER
            rm get-docker.sh
        elif [[ "$OS" == "macos" ]]; then
            brew install --cask docker
        fi
    fi
else
    print_status "Docker is already installed"
fi

# Install Docker Compose
if ! command -v docker-compose &> /dev/null; then
    print_status "Installing Docker Compose..."
    if [[ "$OS" == "linux" ]]; then
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
    elif [[ "$OS" == "macos" ]]; then
        brew install docker-compose
    fi
fi

# Install basic security tools
print_status "Installing basic security tools..."
if [[ "$OS" == "linux" ]]; then
    # Core tools
    TOOLS="nmap nikto dirb hydra john hashcat sqlmap netcat-traditional dnsutils whois"
    
    for tool in $TOOLS; do
        if ! command -v $tool &> /dev/null; then
            print_status "Installing $tool..."
            sudo apt-get install -y $tool 2>/dev/null || print_warning "Failed to install $tool"
        fi
    done
    
elif [[ "$OS" == "macos" ]]; then
    # macOS tools via Homebrew
    TOOLS="nmap nikto hydra john hashcat sqlmap netcat"
    
    for tool in $TOOLS; do
        if ! command -v $tool &> /dev/null; then
            print_status "Installing $tool..."
            brew install $tool 2>/dev/null || print_warning "Failed to install $tool"
        fi
    done
fi

# Install Go (for Go-based tools)
print_status "Checking Go installation..."
if ! command -v go &> /dev/null; then
    print_status "Installing Go..."
    GO_VERSION="1.21.5"
    if [[ "$OS" == "linux" ]]; then
        wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
        rm go${GO_VERSION}.linux-amd64.tar.gz
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
        source ~/.bashrc
    elif [[ "$OS" == "macos" ]]; then
        brew install go
    fi
else
    print_status "Go is already installed"
fi

# Install Go-based tools
print_status "Installing Go-based security tools..."
GO_TOOLS=(
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/ffuf/ffuf@latest"
    "github.com/OJ/gobuster/v3@latest"
    "github.com/OWASP/Amass/v3/...@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    tool_name=$(echo $tool | rev | cut -d'/' -f1 | rev | cut -d'@' -f1)
    if ! command -v $tool_name &> /dev/null; then
        print_status "Installing $tool_name..."
        go install -v $tool 2>/dev/null || print_warning "Failed to install $tool_name"
    fi
done

# Create virtual environment
print_status "Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Install Python requirements
print_status "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install additional Python tools
print_status "Installing Python-based security tools..."
PYTHON_TOOLS=(
    "shodan"
    "censys"
    "theharvester"
    "xsstrike"
    "commix"
    "wafw00f"
)

for tool in "${PYTHON_TOOLS[@]}"; do
    pip install $tool 2>/dev/null || print_warning "Failed to install $tool"
done

# Create necessary directories
print_status "Creating directory structure..."
mkdir -p outputs/scans outputs/reports logs

# Copy environment file
if [ ! -f .env ]; then
    print_status "Creating environment file..."
    cp .env.example .env
    print_warning "Please edit .env file with your API keys"
fi

# Initialize database
print_status "Initializing database..."
python3 -c "from api.routes.security_tools import init_database; init_database()"

# Build Docker images (optional)
print_warning "Would you like to build Docker containers? (y/n)"
read -r response
if [[ "$response" == "y" ]]; then
    print_status "Building Docker images..."
    docker-compose build
fi

# Final checks
print_status "Running final checks..."
echo ""
echo "Installation Summary:"
echo "===================="

# Check installed tools
CHECK_TOOLS="python3 pip nmap nuclei ffuf"
for tool in $CHECK_TOOLS; do
    if command -v $tool &> /dev/null; then
        echo -e "${GREEN}✓${NC} $tool installed"
    else
        echo -e "${RED}✗${NC} $tool not found"
    fi
done

echo ""
print_status "Installation complete!"
echo ""
echo "To start the platform:"
echo "====================="
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run the application: python main.py"
echo "3. Access the platform at: http://localhost:8000"
echo ""
echo "For Docker deployment:"
echo "====================="
echo "docker-compose up -d"
echo ""
print_warning "Remember to add your API keys to the .env file!"