# KALI SECURITY PLATFORM - KULLANIM KILAVUZU

## 🚀 HIZLI BAŞLANGIÇ

### 1. KURULUM (Kali Linux)

```bash
# Projeyi klonla veya kopyala
cd /opt/
git clone <repo-url> kali-security-platform
cd kali-security-platform

# Hızlı kurulum
chmod +x quick_install.sh
./quick_install.sh

# VEYA manuel kurulum
pip3 install -r requirements.txt
python3 main.py
```

### 2. DOCKER İLE ÇALIŞTIRMA

```bash
# Docker image oluştur ve çalıştır
docker-compose up -d

# Logları kontrol et
docker-compose logs -f

# Durdurmak için
docker-compose down
```

### 3. TEST VE KONTROL

```bash
# Platform testlerini çalıştır
python3 test_platform.py

# Eğer hata varsa bağımlılıkları yükle
pip3 install -r requirements.txt
```

## 🌐 WEB ARAYÜZÜ

Platform başlatıldıktan sonra tarayıcınızda açın:
- **Ana Sayfa:** http://localhost:8000
- **Security Tools:** http://localhost:8000/security-tools
- **OSINT Framework:** http://localhost:8000/osint
- **Exploit Advisor:** http://localhost:8000/exploit-advisor

## 📋 ÖZELLİKLER

### Security Tools (130+ Araç)
- Web tarayıcı üzerinden terminal
- Araç kategorileri ve filtreleme
- Komut örnekleri ve açıklamaları
- Gerçek zamanlı çıktı akışı

### OSINT Framework
- 17 OSINT aracı
- Hazır senaryolar
- Adım adım rehberler
- Hedef bazlı araç önerileri

### Exploit Advisor
- Zafiyet-exploit eşleştirme
- Saldırı zinciri oluşturma
- Risk değerlendirmesi
- Exploit komut örnekleri

## ⚙️ YAPILANDIRMA

`.env` dosyasını düzenleyerek özelleştirin:

```env
# Sunucu ayarları
HOST=0.0.0.0
PORT=8000

# Özellikler
ENABLE_TOOL_EXECUTION=true  # Araçları çalıştırmayı etkinleştir

# API Anahtarları (opsiyonel)
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
```

## 🔒 GÜVENLİK UYARILARI

⚠️ **DİKKAT:** Bu platform sadece yasal ve yetkili testler için kullanılmalıdır!

- Hedef sistemlerde sadece yazılı izniniz varsa test yapın
- Araçları kendi sistemlerinizde veya lab ortamında kullanın
- Production ortamında dikkatli olun
- API anahtarlarınızı güvende tutun

## 🛠️ SORUN GİDERME

### Port 8000 kullanımda hatası
```bash
# Başka bir port kullan
PORT=8080 python3 main.py
```

### Modül bulunamadı hatası
```bash
# Bağımlılıkları yeniden yükle
pip3 install --upgrade -r requirements.txt
```

### Docker hatası
```bash
# Docker servisini kontrol et
sudo systemctl status docker
sudo systemctl start docker
```

### Database hatası
```bash
# Database dosyasını sil ve yeniden oluştur
rm security_tools.db
python3 main.py
```

## 📊 PERFORMANS İPUÇLARI

1. **Büyük taramalar için Docker kullanın** - İzolasyon ve kaynak yönetimi
2. **API rate limiting kullanın** - Hedef sistemleri yormamak için
3. **Çıktıları kaydedin** - Önemli bulguları kaybetmemek için
4. **Düzenli yedek alın** - Database ve raporları yedekleyin

## 🤝 DESTEK

Sorunlar için:
1. `test_platform.py` çalıştırın
2. Hata mesajlarını kontrol edin
3. Log dosyalarına bakın: `logs/` dizini
4. GitHub'da issue açın

## 📜 LİSANS

Bu platform eğitim amaçlıdır. Kullanıcılar tüm yasal sorumluluğu kabul eder.

---

**Güvenli testler dileriz! 🛡️**
