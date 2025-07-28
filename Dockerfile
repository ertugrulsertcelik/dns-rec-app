FROM python:3.11-slim
# Çalışma dizinini oluştur
WORKDIR /app
# Gereken dosyaları kopyala
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Uygulama dosyasını kopyala
COPY . .
# Uygulamanın çalışacağı port
EXPOSE 5000
# Uygulamanın başlatılması
CMD ["python3", "app.py"]
