import sys
import json

#  Giriş: python script.py input.txt anka.local output.json

if len(sys.argv) != 4:
    print("Kullanım: python script.py <girdi_dosyası> <alan_adı> <çıktı_dosyası>")
    sys.exit(1)

girdi_dosyasi = sys.argv[1]
alan_adi = sys.argv[2]
cikti_dosyasi = sys.argv[3]

# Dosyadan DNS kayıtlarını oku
try:
    with open(girdi_dosyasi, "r") as f:
        satirlar = f.readlines()
except FileNotFoundError:
    print(f"Hata: '{girdi_dosyasi}' dosyası bulunamadı.")
    sys.exit(1)

json_listesi = []

for satir in satirlar:
    parcalar = satir.strip().split()
    if len(parcalar) >= 4 and parcalar[2] == "A":
        hostname = parcalar[0]
        ip = parcalar[3]
        json_listesi.append({
            "name": f"{hostname}.{alan_adi}",
            "ip": ip
        })

# JSON çıktısını dosyaya yaz
try:
    with open(cikti_dosyasi, "w") as f:
        json.dump(json_listesi, f, indent=4)
    print(f"JSON başarıyla '{cikti_dosyasi}' dosyasına yazıldı.")
except Exception as e:
    print(f"Hata: JSON dosyası yazılamadı → {e}")
