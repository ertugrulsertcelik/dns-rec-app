import os
import re
import subprocess
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash


app = Flask(__name__)
app.secret_key = 'dnsrecapp_secret_key' # Güçlü bir key ile değiştirin

LOG_FILE = 'data/dns_operations.log'
ZONE_PATHS_FILE = 'data/zone_paths.json'
USERS_FILE = 'data/users.json'

# --- User Management ---

def load_users():
    ensure_data_directory()
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    ensure_data_directory()
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def check_login(username, password):
    users = load_users()
    return username in users and users[username] == password

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Login/Logout Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if check_login(username, password):
            session['user'] = username
            return redirect(url_for('index'))
        else:
            flash('Kullanıcı adı veya şifre hatalı', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        if not username or not password:
            flash('Kullanıcı adı ve şifre zorunludur.', 'danger')
        elif password != password2:
            flash('Şifreler eşleşmiyor.', 'danger')
        else:
            users = load_users()
            if username in users:
                flash('Bu kullanıcı adı zaten kayıtlı.', 'danger')
            else:
                users[username] = password
                save_users(users)
                flash('Kayıt başarılı. Giriş yapabilirsiniz.', 'success')
                return redirect(url_for('login'))
    return render_template('register.html')

# --- Uygulamanın geri kalanı ---

# Data klasörünün varlığını kontrol et
def ensure_data_directory():
    if not os.path.exists('data'):
        os.makedirs('data')

# Zone'a özel config dosya adı
def get_config_file(zone):
    if not zone:
        return 'data/dns_config.json'
    # Sadece izin verilen karakterlerle zone adı oluşturulsun (whitelist)
    if not re.match(r'^[a-zA-Z0-9_.-]+$', zone):
        raise ValueError('Geçersiz zone adı (izin verilmeyen karakter)')
    return f'data/dns_config.{zone}.json'

# DNS kayıtlarını ve config'i yükle (zone'a göre)
def load_config(zone=None):
    config_file = get_config_file(zone)
    if not os.path.exists(config_file):
        # Dosya yoksa, zone ismine göre forward/reverse path üret (best practice: forward.zone-adi.xxx)
        if zone:
            # Zone adı whitelist ile kontrol edildiği için güvenli
            forward_zone_path = f'/etc/bind/forward.{zone}'
            reverse_zone_path = f'/etc/bind/reverse.{zone}'
            return {
                'forward_zone_path': forward_zone_path,
                'reverse_zone_path': reverse_zone_path,
                'records': []
            }
        # Zone yoksa hiçbir path dönme (default path yok)
        return {
            'forward_zone_path': '',
            'reverse_zone_path': '',
            'records': []
        }
    # Config dosya yolu path traversal içeriyorsa engelle
    if '..' in config_file or config_file.startswith('/') or config_file.startswith('\\'):
        raise ValueError('Geçersiz config dosya yolu!')
    with open(config_file, 'r') as f:
        return json.load(f)

# Config'i kaydet (zone'a göre)
def save_config(config, zone=None):
    ensure_data_directory()
    config_file = get_config_file(zone)
    # Config dosya yolu path traversal içeriyorsa engelle
    if '..' in config_file or config_file.startswith('/') or config_file.startswith('\\'):
        raise ValueError('Geçersiz config dosya yolu!')
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

# Log ekle
def add_log(action, details):
    ensure_data_directory()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Kullanıcı bilgisini al
    username = session.get('user', 'unknown')
    # Eğer details içinde (zone: None) veya (zone: ) varsa, (zone: default) olarak değiştir
    if '(zone: None)' in details or '(zone: )' in details:
        details = details.replace('(zone: None)', '(zone: default)').replace('(zone: )', '(zone: default)')
    log_entry = f"{timestamp} - {action} - {details} - {username}\n"
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry)

# IP adresi doğrulama
def is_valid_ip(ip):
    # IPv4 için regex ve baştaki sıfırları engelleme
    pattern = r'^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    if ip == '0.0.0.0':
        return False
    for part in parts:
        if len(part) > 1 and part.startswith('0'):
            return False
    return True

# DNS adı doğrulama
def is_valid_dns_name(name):
    # Başta veya sonda tire olmamasını da kontrol etmek için regex'i güncelledik
    pattern = r'^(?!-)[A-Za-z0-9-]+(?<!-)(\.(?!-)[A-Za-z0-9-]+(?<!-))*\.[A-Za-z]{2,}$'
    return re.match(pattern, name) is not None


# Reverse DNS için PTR kaydı oluştur
def create_ptr_record(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return None
    return f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"

# BIND zone dosyalarını güncelle
def update_zone_files(config):
    try:
        # Path traversal ve izin verilen dizin kontrolü
        for path_key in ['forward_zone_path', 'reverse_zone_path']:
            path = config.get(path_key, '')
            if not path.startswith('/etc/bind/forward.') and not path.startswith('/etc/bind/reverse.'):
                raise ValueError(f'İzin verilmeyen zone dosya yolu: {path}')
            if '..' in path or path.startswith('..') or path.startswith('~') or path.startswith('//'):
                raise ValueError(f'Geçersiz zone dosya yolu: {path}')

        # --- FORWARD ZONE -----------------------------------------------------------------------------------------
        if not os.path.exists(config['forward_zone_path']):
            raise FileNotFoundError(f"Forward zone dosyası bulunamadı: {config['forward_zone_path']}")
        with open(config['forward_zone_path'], 'r') as f:
            forward_lines = f.readlines()

        # JSON'daki A kayıtlarını set olarak tut
        json_a_records = set((r['name'].split('.')[0], r['ip']) for r in config['records'])

        # Mevcut dosyadaki A kayıtlarını bul
        new_forward_lines = []
        for line in forward_lines:
            # ns1/ns2 gibi kritik A kayıtlarını ve diğer önemli kayıtları koru
            m = re.match(r'^(\S+)\s+IN\s+A\s+(\S+)', line)
            if m:
                name, ip = m.group(1), m.group(2)
                # ns1 veya ns2 ise her zaman koru
                if name.strip() in ['ns1', 'ns2']:
                    new_forward_lines.append(line)
                    continue
                # Eğer bu kayıt JSON'da yoksa satırı atla (silinmiş demektir)
                if (name, ip) in json_a_records:
                    new_forward_lines.append(line)
                # JSON'da varsa ekle, yoksa sil
                # (edit işlemi için, eski satır silinir, yeni satır eklenir)
            else:
                # NS, CNAME, SOA ve diğer tüm kayıtları koru
                new_forward_lines.append(line)

        # JSON'da olup dosyada olmayan yeni kayıtları ekle
        existing_names_ips = set()
        for line in new_forward_lines:
            m = re.match(r'^(\S+)\s+IN\s+A\s+(\S+)', line)
            if m:
                existing_names_ips.add((m.group(1), m.group(2)))
        for r in config['records']:
            name = r['name'].split('.')[0]
            ip = r['ip']
            if (name, ip) not in existing_names_ips:
                new_forward_lines.append(f"{name}\tIN\tA\t{ip}\n")

        with open(config['forward_zone_path'], 'w') as f:
            f.writelines(new_forward_lines)

        # --- REVERSE ZONE -------------------------------------------------------------------------------------
        if not os.path.exists(config['reverse_zone_path']):
            raise FileNotFoundError(f"Reverse zone dosyası bulunamadı: {config['reverse_zone_path']}")
        with open(config['reverse_zone_path'], 'r') as f:
            reverse_lines = f.readlines()

        # JSON'daki PTR kayıtlarını set olarak tut
        json_ptr_records = set()
        for r in config['records']:
            ptr = create_ptr_record(r['ip'])
            if ptr:
                json_ptr_records.add((ptr, r['name']))

        # Mevcut dosyadaki PTR kayıtlarını bul
        new_reverse_lines = []
        for line in reverse_lines:
            m = re.match(r'^(\S+)\s+IN\s+PTR\s+(\S+)\.?', line)
            if m:
                ptr, name = m.group(1), m.group(2).rstrip('.')
                if (ptr, name) in json_ptr_records:
                    new_reverse_lines.append(line)
                # Aksi halde satırı atla (silinmiş veya editlenmiş)
            else:
                new_reverse_lines.append(line)

        # JSON'da olup dosyada olmayan yeni PTR kayıtlarını ekle
        existing_ptr_names = set()
        for line in new_reverse_lines:
            m = re.match(r'^(\S+)\s+IN\s+PTR\s+(\S+)\.?', line)
            if m:
                existing_ptr_names.add((m.group(1), m.group(2).rstrip('.')))
        for r in config['records']:
            ptr = create_ptr_record(r['ip'])
            if ptr and (ptr, r['name']) not in existing_ptr_names:
                new_reverse_lines.append(f"{ptr}\tIN\tPTR\t{r['name']}.\n")

        with open(config['reverse_zone_path'], 'w') as f:
            f.writelines(new_reverse_lines)

        # BIND'i reload et
        subprocess.run(['sudo', 'rndc', 'reload'], check=True)  
        return True
    except Exception as e:
        add_log('ERROR', f"Zone files update failed: {str(e)}")
        return False
   
@app.route('/')
def root():
    if not session.get('user'):
        return redirect(url_for('login'))
    # Zone parametresi varsa index'e yönlendir, yoksa zone seçimi için index'e git
    zone = request.args.get('zone')
    if zone:
        return redirect(url_for('index', zone=zone))
    return redirect(url_for('index'))

@app.route('/index')
@login_required
def index():
    zone = request.args.get('zone')
    config = load_config(zone)
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()
    logs.reverse()  # En yeni loglar üstte

    # Zone listesi (mevcut config dosyalarından)
    zone_files = [f for f in os.listdir('data') if f.startswith('dns_config.') and f.endswith('.json')]
    zones = [f[11:-5] for f in zone_files if f != 'dns_config.json']

    # Eklenen zone path'lerini oku
    zone_paths = load_zone_paths()  # {'anka.local': {'forward': '/etc/bind/forward.anka.local', ...}, ...}

    return render_template('index.html',
                        records=config['records'],
                        forward_zone_path=config['forward_zone_path'],
                        reverse_zone_path=config['reverse_zone_path'],
                        logs=logs,
                        zones=zones,
                        selected_zone=zone,
                        zone_paths=zone_paths)

# Zone'a göre kayıt ekle
@app.route('/add', methods=['POST'])
@login_required
def add_record():
    ip = request.form.get('ip')
    name = request.form.get('name')
    zone = request.form.get('zone')

    # --- DNS adı kısa ise zone ile tamamla ---
    name = ensure_fqdn(name, zone)

    # Label sayısı kontrolü (ör: example.ex.anka.local = 4 Label)
    if len(name.split('.')) > 4:
        return jsonify({'success': False, 'message': 'DNS adı en fazla 4 Labeldan oluşabilir (örn: host.sub.zone.tld)'})

    if not is_valid_ip(ip):
        return jsonify({'success': False, 'message': 'Geçersiz IP adresi'})

    if not is_valid_dns_name(name):
        return jsonify({'success': False, 'message': 'Geçersiz DNS adı'})

    config = load_config(zone)

    # Dosya yolları gerçekten var mı kontrol et
    if not os.path.exists(config['forward_zone_path']) or not os.path.exists(config['reverse_zone_path']):
        return jsonify({'success': False, 'message': 'Zone dosya yolu bulunamadı. Lütfen geçerli bir forward/reverse path girin.'})
    # Aynı DNS adı ve aynı IP varsa engelle, farklı IP'ye izin ver
    for record in config['records']:
        if record['name'] == name and record['ip'] == ip:
            return jsonify({'success': False, 'message': 'Bu DNS adı ve IP adresi zaten mevcut'})
        # Aynı hostname başka bir IP ile varsa engelle
        if record['name'] == name and record['ip'] != ip:
            return jsonify({'success': False, 'message': 'Bu DNS adı başka bir IP adresine zaten atanmış'})

    config['records'].append({'name': name, 'ip': ip})
    save_config(config, zone)

    if update_zone_files(config):
        add_log('ADD', f"Added record: {name} -> {ip} (zone: {zone})")
        return jsonify({'success': True, 'record': {'name': name, 'ip': ip}})
    else:
        return jsonify({'success': False, 'message': 'Zone files güncellenirken hata oluştu'})


# Zone'a göre kayıt sil
@app.route('/delete/<int:index>', methods=['POST'])
@login_required
def delete_record(index):
    zone = request.form.get('zone')
    config = load_config(zone)

    # Dosya yolları gerçekten var mı kontrol et
    if not os.path.exists(config['forward_zone_path']) or not os.path.exists(config['reverse_zone_path']):
        return jsonify({'success': False, 'message': 'Zone dosya yolu bulunamadı. Lütfen geçerli bir forward/reverse path girin.'})
    try:
        index = int(index)
    except Exception:
        return jsonify({'success': False, 'message': 'Geçersiz kayıt indeksi (tip hatası)'})
    if not config['records']:
        return jsonify({'success': False, 'message': 'Silinecek kayıt yok'})
    if index < 0 or index >= len(config['records']):
        return jsonify({'success': False, 'message': 'Geçersiz kayıt indeksi'})

    deleted_record = config['records'].pop(index)
    save_config(config, zone)

    if update_zone_files(config):
        add_log('DELETE', f"Deleted record: {deleted_record['name']} -> {deleted_record['ip']} (zone: {zone})")
        return jsonify({'success': True, 'index': index})
    else:
        return jsonify({'success': False, 'message': 'Zone files güncellenirken hata oluştu'})


# Zone'a göre kayıt düzenle
@app.route('/edit/<int:index>', methods=['POST'])
@login_required
def edit_record(index):
    ip = request.form.get('ip')
    name = request.form.get('name')
    zone = request.form.get('zone')

    # --- DNS adı kısa ise zone ile tamamla ---
    name = ensure_fqdn(name, zone)

    # Label sayısı kontrolü (ör: example.ex.anka.local = 4 Label)
    if len(name.split('.')) > 4:
        return jsonify({'success': False, 'message': 'DNS adı en fazla 4 Labeldan oluşabilir (örn: host.sub.zone.tld)'})

    if not is_valid_ip(ip):
        return jsonify({'success': False, 'message': 'Geçersiz IP adresi'})

    if not is_valid_dns_name(name):
        return jsonify({'success': False, 'message': 'Geçersiz DNS adı'})

    config = load_config(zone)

    # Dosya yolları gerçekten var mı kontrol et
    if not os.path.exists(config['forward_zone_path']) or not os.path.exists(config['reverse_zone_path']):
        return jsonify({'success': False, 'message': 'Zone dosya yolu bulunamadı. Lütfen geçerli bir forward/reverse path girin.'})
    if index < 0 or index >= len(config['records']):
        return jsonify({'success': False, 'message': 'Geçersiz kayıt indeksi'})

    # Aynı hostname başka bir IP ile varsa engelle (edit edilen kayıt hariç)
    for i, record in enumerate(config['records']):
        if i != index and record['name'] == name:
            return jsonify({'success': False, 'message': 'Bu DNS adı başka bir IP adresine zaten atanmış'})

    old_record = config['records'][index]
    config['records'][index] = {'name': name, 'ip': ip}
    save_config(config, zone)

    if update_zone_files(config):
        add_log('EDIT', f"Edited record: {old_record['name']}({old_record['ip']}) -> {name}({ip}) (zone: {zone})")
        return jsonify({'success': True, 'record': {'name': name, 'ip': ip}, 'index': index})
    else:
        return jsonify({'success': False, 'message': 'Zone files güncellenirken hata oluştu'})


# Zone'a göre zone dosya yollarını güncelle
@app.route('/update_zone_paths', methods=['POST'])
@login_required
def update_zone_paths():
    forward_path = request.form.get('forward_path')
    reverse_path = request.form.get('reverse_path')
    zone = request.form.get('zone')

    # Path traversal ve izin verilen dizin kontrolü
    for path in [forward_path, reverse_path]:
        if not path.startswith('/etc/bind/forward.') and not path.startswith('/etc/bind/reverse.'):
            return jsonify({'success': False, 'message': f'İzin verilmeyen zone dosya yolu: {path}'})
        if '..' in path or path.startswith('..') or path.startswith('~') or path.startswith('//'):
            return jsonify({'success': False, 'message': f'Geçersiz zone dosya yolu: {path}'})

    # Dosya yolları gerçekten var mı kontrol et
    if not os.path.exists(forward_path) or not os.path.exists(reverse_path):
        return jsonify({'success': False, 'message': 'Zone dosya yolu bulunamadı. Lütfen geçerli bir forward/reverse path girin.'})

    # forward_path'ten zone adını çıkar
    def extract_zone_from_path(path):
        base = os.path.basename(path)
        if base.startswith('forward.'):
            return base[len('forward.'):]
        elif base.startswith('reverse.'):
            return base[len('reverse.'):]
        return None

    new_zone = extract_zone_from_path(forward_path)
    if new_zone:
        zone = new_zone
    config = load_config(zone)  # Her durumda doğru JSON'u yükle
    config['forward_zone_path'] = forward_path
    config['reverse_zone_path'] = reverse_path
    save_config(config, zone)

    # --- ZONE PATHS JSON'A EKLE/GÜNCELLE ---
    zone_paths = load_zone_paths()
    zone_paths[zone] = {
        'forward': forward_path,
        'reverse': reverse_path
    }
    save_zone_paths(zone_paths)

    add_log('CONFIG', f"Zone paths updated - Forward: {forward_path}, Reverse: {reverse_path} (zone: {zone})")
    # Güncel kayıt listesini ve yolları döndür
    return jsonify({
        'success': True,
        'records': config['records'],
        'forward_zone_path': config['forward_zone_path'],
        'reverse_zone_path': config['reverse_zone_path'],
        'zone': zone,
        'zone_paths': zone_paths
    })

@app.route('/nslookup/<name>')
@login_required
def run_nslookup(name):
    zone = request.args.get('zone')
    try:
        result = subprocess.run(['nslookup', name], capture_output=True, text=True)
        output = result.stdout if result.returncode == 0 else result.stderr
        return jsonify({'success': result.returncode == 0, 'output': output})
    except Exception as e:
        return jsonify({'success': False, 'output': str(e)})

@app.route('/logs')
@login_required
def show_logs():
    log_path = os.path.join('data', 'dns_operations.log')
    logs = []
    if os.path.exists(log_path):
        with open(log_path, 'r', encoding='utf-8') as f:
            logs = f.readlines()
    return render_template('logs.html', logs=logs)

def load_zone_paths():
    try:
        ensure_data_directory()
        if not os.path.exists(ZONE_PATHS_FILE):
            return {}
        with open(ZONE_PATHS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Zone paths yüklenirken hata: {e}")
        return {}

def save_zone_paths(zone_paths):
    ensure_data_directory()
    with open(ZONE_PATHS_FILE, 'w') as f:
        json.dump(zone_paths, f, indent=4)

def ensure_fqdn(name, zone):
    """
    Eğer name tam bir FQDN değilse ve zone varsa, sonuna zone ekle.
    """
    if not zone:
        return name
    if name.endswith('.' + zone):
        return name
    # Eğer name zaten bir FQDN ise (ör: deneme1.anka.local), dokunma
    if '.' in name and name.split('.')[-2] + '.' + name.split('.')[-1] == zone:
        return name
    # Sadece kısa isimse ekle
    return f"{name}.{zone}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)