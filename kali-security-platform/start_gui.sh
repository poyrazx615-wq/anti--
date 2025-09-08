#!/bin/bash

################################################################################
#                     KALI SECURITY PLATFORM GUI LAUNCHER                     #
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║              KALI SECURITY PLATFORM - GUI LAUNCHER                          ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check which GUI to launch
echo -e "${BLUE}[?] Hangi arayüzü başlatmak istersiniz?${NC}"
echo "1) Web Arayüzü (Browser)"
echo "2) Desktop Uygulaması (PyQt5)"
echo "3) Her İkisi"
echo -n "Seçiminiz (1-3): "
read choice

case $choice in
    1)
        echo -e "${GREEN}[+] Web arayüzü başlatılıyor...${NC}"
        
        # Start backend
        cd /opt/kali-security-platform
        source venv/bin/activate
        
        # Start main application
        python main.py &
        MAIN_PID=$!
        
        sleep 3
        
        # Open browser
        echo -e "${GREEN}[+] Tarayıcı açılıyor...${NC}"
        xdg-open https://localhost:8000 2>/dev/null || firefox https://localhost:8000 &
        
        echo -e "${GREEN}[✓] Web arayüzü başlatıldı!${NC}"
        echo -e "${YELLOW}[!] Kapatmak için Ctrl+C kullanın${NC}"
        
        # Wait for interrupt
        trap "kill $MAIN_PID; exit" INT
        wait $MAIN_PID
        ;;
        
    2)
        echo -e "${GREEN}[+] Desktop uygulaması başlatılıyor...${NC}"
        
        # Check PyQt5
        if ! python3 -c "import PyQt5" 2>/dev/null; then
            echo -e "${YELLOW}[!] PyQt5 kurulu değil, kuruluyor...${NC}"
            pip3 install PyQt5 PyQt5-tools PyQtWebEngine qtawesome
        fi
        
        # Start desktop app
        cd /opt/kali-security-platform/gui
        python3 desktop_app.py &
        DESKTOP_PID=$!
        
        echo -e "${GREEN}[✓] Desktop uygulaması başlatıldı!${NC}"
        
        # Wait for app to close
        wait $DESKTOP_PID
        ;;
        
    3)
        echo -e "${GREEN}[+] Her iki arayüz başlatılıyor...${NC}"
        
        # Start backend
        cd /opt/kali-security-platform
        source venv/bin/activate
        python main.py &
        MAIN_PID=$!
        
        sleep 3
        
        # Start desktop app
        cd gui
        python3 desktop_app.py &
        DESKTOP_PID=$!
        
        # Open browser
        xdg-open https://localhost:8000 2>/dev/null &
        
        echo -e "${GREEN}[✓] Tüm arayüzler başlatıldı!${NC}"
        echo -e "${YELLOW}[!] Kapatmak için Ctrl+C kullanın${NC}"
        
        # Wait for interrupt
        trap "kill $MAIN_PID $DESKTOP_PID; exit" INT
        wait $MAIN_PID $DESKTOP_PID
        ;;
        
    *)
        echo -e "${RED}[!] Geçersiz seçim${NC}"
        exit 1
        ;;
esac