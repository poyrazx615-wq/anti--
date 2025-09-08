#!/bin/bash

################################################################################
#                     KALI SECURITY PLATFORM - KURULUM SCRIPTI                #
#                         Anti-Security Team - v5.0                           #
#                    "Bozmadan düzeltemezsin, önce bozmayı öğren!"           #
################################################################################

set -e  # Hata durumunda dur

# Renkli output için değişkenler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
function show_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║              KALI SECURITY PLATFORM - PROFESSIONAL EDITION                  ║
║                    Automated Penetration Testing Framework                   ║
║                         Kali Linux Integration Suite                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Log fonksiyonu
function log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

function log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Root kontrolü
function check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Bu script root olarak çalıştırılmalıdır!"
        exit 1
    fi
}

# Kali Linux kontrolü
function check_kali() {
    if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
        log_warning "Kali Linux tespit edilemedi!"
        read -p "Devam etmek istiyor musunuz? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log_success "Kali Linux tespit edildi"
    fi
}

# Sistem güncellemesi
function update_system() {
    log_info "Sistem güncelleniyor..."
    apt-get update -y
    apt-get upgrade -y
    apt-get dist-upgrade -y
    apt-get autoremove -y
    apt-get autoclean -y
    log_success "Sistem güncellendi"
}

# Temel bağımlılıkları kur
function install_base_dependencies() {
    log_info "Temel bağımlılıklar kuruluyor..."
    
    # Development tools
    apt-get install -y \
        build-essential \
        cmake \
        gcc \
        g++ \
        make \
        git \
        curl \
        wget \
        vim \
        htop \
        net-tools \
        software-properties-common
    
    # Python ve pip
    apt-get install -y \
        python3 \
        python3-pip \
        python3-dev \
        python3-venv \
        python3-setuptools
    
    # Database
    apt-get install -y \
        postgresql \
        postgresql-contrib \
        redis-server \
        mongodb \
        sqlite3
    
    # Libraries
    apt-get install -y \
        libssl-dev \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        libpcap-dev \
        libgmp-dev \
        libmpfr-dev \
        libmpc-dev
    
    log_success "Temel bağımlılıklar kuruldu"
}

# Kali araçlarını kontrol et ve kur
function install_kali_tools() {
    log_info "Kali araçları kontrol ediliyor ve kuruluyor..."
    
    # Network Tools
    tools_network=(
        "nmap"
        "masscan"
        "netcat"
        "tcpdump"
        "wireshark"
        "aircrack-ng"
        "ettercap-text-only"
        "dsniff"
        "arpspoof"
        "macchanger"
    )
    
    # Web Application Tools
    tools_web=(
        "burpsuite"
        "zaproxy"
        "nikto"
        "dirb"
        "dirbuster"
        "gobuster"
        "wfuzz"
        "sqlmap"
        "commix"
        "whatweb"
    )
    
    # Vulnerability Assessment
    tools_vuln=(
        "metasploit-framework"
        "searchsploit"
        "exploitdb"
        "lynis"
        "openvas"
        "wpscan"
        "joomscan"
    )
    
    # Password Tools
    tools_password=(
        "john"
        "hashcat"
        "hydra"
        "medusa"
        "crunch"
        "cewl"
    )
    
    # Information Gathering
    tools_recon=(
        "theharvester"
        "recon-ng"
        "maltego"
        "shodan"
        "spiderfoot"
        "osrframework"
        "sublist3r"
    )
    
    # Exploitation Tools
    tools_exploit=(
        "armitage"
        "beef-xss"
        "set"
        "shellter"
        "veil"
        "empire"
    )
    
    # Tüm araçları kur
    all_tools=("${tools_network[@]}" "${tools_web[@]}" "${tools_vuln[@]}" "${tools_password[@]}" "${tools_recon[@]}" "${tools_exploit[@]}")
    
    for tool in "${all_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_warning "$tool bulunamadı, kuruluyor..."
            apt-get install -y "$tool" 2>/dev/null || log_error "$tool kurulamadı"
        else
            log_success "$tool zaten kurulu"
        fi
    done
    
    log_success "Kali araçları kuruldu"
}

# Python sanal ortam oluştur
function setup_python_env() {
    log_info "Python sanal ortamı oluşturuluyor..."
    
    # Proje dizinine geç
    cd /opt/kali-security-platform
    
    # Sanal ortam oluştur
    python3 -m venv venv
    source venv/bin/activate
    
    # pip güncelle
    pip install --upgrade pip setuptools wheel
    
    # Requirements kur
    pip install -r requirements.txt
    
    log_success "Python ortamı hazır"
}

# PostgreSQL veritabanı kur
function setup_database() {
    log_info "PostgreSQL veritabanı yapılandırılıyor..."
    
    # PostgreSQL başlat
    systemctl start postgresql
    systemctl enable postgresql
    
    # Veritabanı ve kullanıcı oluştur
    sudo -u postgres psql <<EOF
CREATE USER antisecurity WITH PASSWORD 'AntiSec2024!';
CREATE DATABASE security_platform OWNER antisecurity;
GRANT ALL PRIVILEGES ON DATABASE security_platform TO antisecurity;
\q
EOF
    
    # Redis başlat
    systemctl start redis-server
    systemctl enable redis-server
    
    log_success "Veritabanı yapılandırıldı"
}

# C++ modüllerini derle
function compile_cpp_modules() {
    log_info "C++ modülleri derleniyor..."
    
    cd /opt/kali-security-platform/core/cpp
    
    # Build dizini oluştur
    mkdir -p build
    cd build
    
    # CMake ile derle
    cmake ..
    make -j$(nproc)
    make install
    
    log_success "C++ modülleri derlendi"
}

# Servis dosyalarını oluştur
function create_services() {
    log_info "Systemd servisleri oluşturuluyor..."
    
    # Ana servis
    cat > /etc/systemd/system/security-platform.service <<EOF
[Unit]
Description=Kali Security Platform
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/kali-security-platform
Environment="PATH=/opt/kali-security-platform/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/kali-security-platform/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Worker servis
    cat > /etc/systemd/system/security-worker.service <<EOF
[Unit]
Description=Security Platform Worker
After=network.target security-platform.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/kali-security-platform
Environment="PATH=/opt/kali-security-platform/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/kali-security-platform/venv/bin/celery -A core.tasks worker --loglevel=info
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Scheduler servis
    cat > /etc/systemd/system/security-scheduler.service <<EOF
[Unit]
Description=Security Platform Scheduler
After=network.target security-platform.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/kali-security-platform
Environment="PATH=/opt/kali-security-platform/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/kali-security-platform/venv/bin/celery -A core.tasks beat --loglevel=info
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    log_success "Servisler oluşturuldu"
}

# Nginx yapılandırması
function setup_nginx() {
    log_info "Nginx yapılandırılıyor..."
    
    apt-get install -y nginx
    
    # SSL sertifikası oluştur
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/platform.key \
        -out /etc/nginx/ssl/platform.crt \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=AntiSecurity/CN=localhost"
    
    # Nginx config
    cat > /etc/nginx/sites-available/security-platform <<EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name _;
    
    ssl_certificate /etc/nginx/ssl/platform.crt;
    ssl_certificate_key /etc/nginx/ssl/platform.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    client_max_body_size 100M;
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/security-platform /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    systemctl restart nginx
    systemctl enable nginx
    
    log_success "Nginx yapılandırıldı"
}

# Firewall yapılandırması
function setup_firewall() {
    log_info "Firewall yapılandırılıyor..."
    
    # UFW kur ve yapılandır
    apt-get install -y ufw
    
    # Varsayılan politikalar
    ufw default deny incoming
    ufw default allow outgoing
    
    # İzin verilen portlar
    ufw allow 22/tcp    # SSH
    ufw allow 80/tcp    # HTTP
    ufw allow 443/tcp   # HTTPS
    ufw allow 8000/tcp  # API
    
    # UFW'yi etkinleştir
    echo "y" | ufw enable
    
    log_success "Firewall yapılandırıldı"
}

# Cron job'ları oluştur
function setup_cron() {
    log_info "Cron job'ları oluşturuluyor..."
    
    # Günlük backup
    cat > /etc/cron.d/security-platform <<EOF
# Günlük veritabanı backup
0 2 * * * root /opt/kali-security-platform/scripts/backup.sh

# Haftalık güncelleme kontrolü
0 3 * * 0 root /opt/kali-security-platform/scripts/update.sh

# Log temizleme (30 günden eski)
0 4 * * * root find /opt/kali-security-platform/logs -type f -mtime +30 -delete
EOF
    
    log_success "Cron job'ları oluşturuldu"
}

# Ana kurulum fonksiyonu
function main() {
    show_banner
    
    log_info "Kurulum başlatılıyor..."
    
    # Kontroller
    check_root
    check_kali
    
    # Platform dizinini oluştur
    log_info "Platform dizini oluşturuluyor..."
    mkdir -p /opt/kali-security-platform
    cp -r ./* /opt/kali-security-platform/
    
    # Kurulum adımları
    update_system
    install_base_dependencies
    install_kali_tools
    setup_python_env
    setup_database
    compile_cpp_modules
    create_services
    setup_nginx
    setup_firewall
    setup_cron
    
    # İzinleri ayarla
    chmod +x /opt/kali-security-platform/*.py
    chmod +x /opt/kali-security-platform/scripts/*.sh
    
    # Servisleri başlat
    log_info "Servisler başlatılıyor..."
    systemctl start security-platform
    systemctl enable security-platform
    systemctl start security-worker
    systemctl enable security-worker
    systemctl start security-scheduler
    systemctl enable security-scheduler
    
    # Kurulum özeti
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                         KURULUM TAMAMLANDI!                                 ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "${CYAN}Platform Bilgileri:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "Web Arayüzü:     ${GREEN}https://localhost${NC}"
    echo -e "API Endpoint:    ${GREEN}https://localhost/api${NC}"
    echo -e "Dokümantasyon:   ${GREEN}https://localhost/docs${NC}"
    echo -e "Platform Dizini: ${GREEN}/opt/kali-security-platform${NC}"
    echo ""
    echo -e "${YELLOW}Varsayılan Kimlikler:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Kullanıcı: admin"
    echo "Şifre: AntiSec2024!"
    echo ""
    echo -e "${RED}⚠️  GÜVENLİK UYARISI:${NC}"
    echo "1. Varsayılan şifreyi hemen değiştirin!"
    echo "2. Platform sadece yasal ve etik amaçlar için kullanılmalıdır!"
    echo "3. Hedef sistemler için yazılı izin alınmalıdır!"
    echo ""
    echo -e "${GREEN}Platform başarıyla kuruldu ve çalışıyor!${NC}"
}

# Scripti çalıştır
main "$@"