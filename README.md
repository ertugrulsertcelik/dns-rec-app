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

### 2. BIND9 Konfigürasyonu (Opsiyonel)

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

# Uygulamayı dizine kopyala
sudo cp -r /path/to/your/app/* .

# Python virtual environment oluştur (Opsiyonel venv ortamda kurmak isterseniz)
python3 -m venv venv
source venv/bin/activate

## Seçenek 2: Kubernetes ile Kurulum

# Kubernetes deployment'ı uygula
kubectl apply -f dns-app.yaml

# Service'i kontrol et
kubectl get services

```

### 7. Service Konfigürasyonu

```bash
# Service dosyası oluşturulmuş halde dökümanda bulunuyor gerekli konfigürsayonları kendiniz düzenleyebilirsiniz

sudo mv services/dns-rec-app.service /etc/systemd/system

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

### 4. Eski DNS Kayıtlarını Aktarma
```bash
#Uygulama'nın çalıştırılması
python3 rec_to_json.py records.txt example.local json.txt 

#Tanımlar
python3 ⟶ kodu çalıştırmak için
rec_to_json ⟶ uygulama 
records ⟶ eski dns kayıtları (forward) dosyası

auth7	IN	A	133.101.173.247
user12	IN	A	155.71.222.102 

Şeklinde kayıtları sırayla records.txt dosyasına ekle 

example.local ⟶ alan adını gir 
json.txt ⟶ json formatındaki çıktının yazılacağı dosyayı ekle 

Çalıştırıldığında tüm kayıtlarınız .json formatına dönüşmüş olacak…

JSON formatında oluşan yeni kayıtları data klasörü altındaki config dosyasına ekleyebilirsiniz
```

## 🚨 Kritik Güvenlik Notları


### 1. Dosya İzinleri
- Zone dosyaları sadece BIND9 tarafından yazılabilir olmalı
- Uygulama data dizini güvenli olmalı
- Log dosyaları düzenli olarak rotate edilmeli


### Yaygın Sorunlar ve Çözümleri

- **Uygulama başlamıyor**
   - Port 5000 kullanımda mı kontrol et
   - Python bağımlılıkları eksik mi kontrol et
   - Log dosyalarını kontrol et

- **DNS sorguları çalışmıyor**
   - BIND9 çalışıyor mu kontrol et
   - Zone dosyaları doğru mu kontrol et
   - Firewall kuralları doğru mu kontrol et

- **Zone dosyaları güncellenmiyor**
   - Dosya izinleri doğru mu kontrol et
   - BIND9 yazma izni var mı kontrol et

## 📚 Ek Kaynaklar

- [BIND9 Administrator Reference Manual](https://bind9.readthedocs.io/)
- [Flask Security Best Practices](https://flask-security.readthedocs.io/)
- [DNS Security Best Practices](https://www.ietf.org/rfc/rfc4033.txt)
- [Systemd Service Configuration](https://www.freedesktop.org/software/systemd/man/systemd.service.html)


🚨 Not: Bu rehber production ortamı için hazırlanmıştır. Test ortamında önce deneyin ve güvenlik gereksinimlerinize göre uyarlayın. 