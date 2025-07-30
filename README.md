# dns-rec-app
# DNS Kayıt Uygulaması 

## 📋 Ön Gereksinimler

### Sistem Gereksinimleri
- **İşletim Sistemi**: Ubuntu 20.04+

### Yazılım Gereksinimleri
- **BIND9**: DNS sunucusu
- **Docker** (opsiyonel, container deployment için)
- **Kubernetes** (opsiyonel, cluster deployment için)

## 🔧 Kurulum Adımları

### 1. Sistem Hazırlığı

```bash
# Sistem güncellemelerini yap
sudo apt update && sudo apt upgrade -y

# Gerekli paketleri yükle
sudo apt install -y python3 python3-pip python3-venv python3-flask
sudo apt install -y bind9 bind9utils
```

### 2. BIND9 Konfigürasyonu

```bash
# BIND9 servisini başlat
sudo systemctl start named
sudo systemctl enable named

# BIND9 konfigürasyonunu kontrol et
sudo named-checkconf /etc/bind/named.conf

# Zone dosyalarını oluştur (örnek)
sudo touch /etc/bind/forward.example.com
sudo touch /etc/bind/reverse.example.com
```

### 3. Uygulama Kurulumu

## Seçenek 1: Standart Kurulum

```bash
# Uygulama dizinini oluştur
sudo mkdir -p /app/dns-rec-app
cd /app/dns-rec-app

# Uygulamayı kopyala
sudo cp -r /path/to/your/app/* .

# Python virtual environment oluştur
python3 -m venv venv
source venv/bin/activate

## Seçenek 2: Kubernetes ile Kurulum

```bash
# Kubernetes deployment'ı uygula
kubectl apply -f dns-app.yaml

# Service'i kontrol et
kubectl get services

```

### 7. Service Konfigürasyonu

```bash
# Service dosyası oluşturuldu gerekli konfigürsayonları kendiniz düzenleyebilirsiniz

sudo mv dns-rec-app.service /etc/systemd/system

```


```bash
# Service'i etkinleştir
sudo systemctl daemon-reload
sudo systemctl enable dns-rec-app.service
sudo systemctl start dns-rec-app.service
```

## 🔍 Kurulum Sonrası Kontroller

### 1. Uygulama Kontrolleri

```bash
# Uygulama durumunu kontrol et
sudo systemctl status dns-rec-app.service

# Logları kontrol et
sudo journalctl -u dns-rec-app -f

# Web arayüzünü test et
curl http://localhost:5000
```

### 2. DNS Kontrolleri

```bash
# BIND9 durumunu kontrol et
sudo systemctl status named

# DNS sorgularını test et
nslookup example.com localhost
dig @localhost example.com

# Zone dosyalarını kontrol et
sudo named-checkzone example.com /etc/bind/zones/forward.example.com
```

### 3. Güvenlik Kontrolleri

```bash
# Port taraması
sudo netstat -tlnp | grep :5000

# Firewall durumu
sudo ufw status
```

## 🚨 Kritik Güvenlik Notları


### 1. Dosya İzinleri
- Zone dosyaları sadece BIND9 tarafından yazılabilir olmalı
- Uygulama data dizini güvenli olmalı
- Log dosyaları düzenli olarak rotate edilmeli


```


### Yaygın Sorunlar ve Çözümleri

1. **Uygulama başlamıyor**
   - Port 5000 kullanımda mı kontrol et
   - Python bağımlılıkları eksik mi kontrol et
   - Log dosyalarını kontrol et

2. **DNS sorguları çalışmıyor**
   - BIND9 çalışıyor mu kontrol et
   - Zone dosyaları doğru mu kontrol et
   - Firewall kuralları doğru mu kontrol et

3. **Zone dosyaları güncellenmiyor**
   - Dosya izinleri doğru mu kontrol et
   - BIND9 yazma izni var mı kontrol et

## 📚 Ek Kaynaklar

- [BIND9 Administrator Reference Manual](https://bind9.readthedocs.io/)
- [Flask Security Best Practices](https://flask-security.readthedocs.io/)
- [DNS Security Best Practices](https://www.ietf.org/rfc/rfc4033.txt)
- [Systemd Service Configuration](https://www.freedesktop.org/software/systemd/man/systemd.service.html)

---

**Not**: Bu rehber production ortamı için hazırlanmıştır. Test ortamında önce deneyin ve güvenlik gereksinimlerinize göre uyarlayın. 