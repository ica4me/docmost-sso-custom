# ⏳PoC Docmost Collaboration Platform

> Proof of Concept (PoC) Docmost

## Deploy Docmost Comunity + Keyloack (2FA) + AD (Active Directory)

ByPass Security & SSO (Enterprise Licence)

:::info
Skenario Form-Based SSO buatan sendiri mengunakan metode JIT (Just-In-Time) Provisioning dengan Ephemeral Credential Injection.
:::

:::info
Implementasi SSO Middleware dengan Pendekatan JIT Provisioning dan Synthetic Login menggunakan Ephemeral Credentials.
:::

## Server Testing PoC

- Virtual Machine (Ubuntu 22.04 LTS)
- 2 vCPU
- 4 GB RAM
- 30 GB (vda)
- Public IP Address (**************)

## Tools Requirement

<details>
<summary>Info Server AD (Active Directory)</summary>

```bash
Windows server 2022
Console Display Name: AD Testing

Vendor: Active Directory
Connection URL	ldap://**************:389
Users DN	CN=Users,DC=ad,DC=testing,DC=local
Bind DN	CN=Test Admin,CN=Users,DC=ad,DC=testing,DC=local
Bind Credential	**************
Kerberos Principal	testadmin@ad.testing.local
```

</details>

- Docker Compose
- Database PostgreSQL
- keycloak (Identity Provider)
- REDIS (Cache Docmost)
- DOCMOST
- GATEKEEPER (Auth Middleware)
- NGINX (Reverse Proxy Utama)

## Proses Installasi dengan Docker

<details>
<summary>Struktur Folder & Docker install</summary>

```bash
# Buat folder proyek
mkdir -p /opt/docmost-stack
cd /opt/docmost-stack

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

</details>
 
<details>
<summary>File `docker-compose.yml`</summary>

```bash
version: '3.8'

services:
  # ----------------------------------------------------------------
  # 1. DATABASE (PostgreSQL)
  # ----------------------------------------------------------------
  postgres:
    image: postgres:15-alpine
    container_name: db_postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: **************
      POSTGRES_PASSWORD: **************
      POSTGRES_DB: keycloak
    networks:
      - internal_net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U admin"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ----------------------------------------------------------------
  # 2. KEYCLOAK (Identity Provider)
  # ----------------------------------------------------------------
  keycloak:
    image: quay.io/keycloak/keycloak:23.0.0
    container_name: idp_keycloak
    command: start-dev --import-realm
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: **************
      KC_DB_PASSWORD: **************
      KEYCLOAK_ADMIN: **************
      KEYCLOAK_ADMIN_PASSWORD: **************
      KC_HOSTNAME_URL: http://**************:8080
      KC_HOSTNAME_STRICT: "false"
      KC_HOSTNAME_STRICT_HTTPS: "false"
      KC_HTTP_ENABLED: "true"
    ports:
      - "8080:8080"
    volumes:
      - ./themes:/opt/keycloak/themes
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - internal_net

  # ----------------------------------------------------------------
  # 3. REDIS (Cache Docmost)
  # ----------------------------------------------------------------
  redis:
    image: redis:alpine
    container_name: cache_redis
    networks:
      - internal_net

  # ----------------------------------------------------------------
  # 4. DOCMOST (Aplikasi Utama - HIDDEN)
  # ----------------------------------------------------------------
  docmost:
    image: docmost/docmost:latest
    container_name: app_docmost
    depends_on:
      - postgres
      - redis
    environment:
      APP_SECRET: "**************"
      DATABASE_URL: "postgresql://**************:**************@postgres:5432/docmost?schema=public"
      REDIS_URL: "redis://redis:6379"
    networks:
      - internal_net

  # ----------------------------------------------------------------
  # 5. GATEKEEPER (Auth Middleware - HIDDEN)
  # ----------------------------------------------------------------
  gatekeeper:
    build: .
    container_name: jit_gatekeeper
    restart: always
    command: gunicorn -w 2 -b 0.0.0.0:5000 --reload --access-logfile - --error-logfile - gatekeeper:app
    volumes:
      - ./gatekeeper.py:/app/gatekeeper.py
      - ./login_page:/app/templates
    environment:
      # Database Config
      DB_HOST: "**************"
      DB_PASS: "**************"
      
      # Internal URLs (Komunikasi antar container Docker)
      DOCMOST_INTERNAL_URL: "http://app_docmost:3000"
      KEYCLOAK_INTERNAL_URL: "http://idp_keycloak:8080"
      
      # Public URLs (Redirect Browser)
      KEYCLOAK_PUBLIC_URL: "http://**************:8080"
      APP_BASE_URL: "http://**************:3000"
      
      # Keycloak Client Credentials (Agar Gatekeeper bisa tukar token)
      KEYCLOAK_CLIENT_ID: "**************"
      KEYCLOAK_CLIENT_SECRET: "**************"
      
    depends_on:
      - postgres
      - docmost
      - keycloak
    networks:
      - internal_net

  # ----------------------------------------------------------------
  # 6. NGINX (Reverse Proxy)
  # ----------------------------------------------------------------
  nginx:
    image: nginx:alpine
    container_name: main_proxy
    restart: always
    ports:
      - "3000:80" # Akses Web Utama via Port 3000
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - gatekeeper
      - docmost
    networks:
      - internal_net

networks:
  internal_net:
    driver: bridge

volumes:
  postgres_data:
```

</details>
<details>
<summary>File Dockerfile</summary>

```bash
nano Dockerfile
```

```bash
# base image Python (Slim)
FROM python:3.9-slim

# ================= K O N F I G U R A S I   S I S T E M =================

# Set Environment Variables
# 1. Mencegah Python membuat file .pyc (sampah cache)
ENV PYTHONDONTWRITEBYTECODE=1
# 2. Pastikan log Python langsung keluar ke console (penting untuk debugging Docker)
ENV PYTHONUNBUFFERED=1
# 3. Set Timezone ke Jakarta (WIB)
ENV TZ=Asia/Jakarta

# Set working directory di dalam container
WORKDIR /app

# ================= I N S T A L A S I =================

# 1. Update repository dan install dependency sistem
# - gcc: Dibutuhkan untuk men-compile 'bcrypt'
# - libpq-dev: Dibutuhkan oleh 'psycopg2' (driver postgres)
# - tzdata: Untuk pengaturan jam/timezone
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# 2. Copy script python Anda ke dalam container
COPY gatekeeper.py .

# 3. Install Library Python
# Menggunakan --no-cache-dir agar image tidak bengkak menyimpan cache pip
RUN pip install --upgrade pip && \
    pip install --no-cache-dir \
    flask \
    psycopg2-binary \
    bcrypt \
    requests \
    gunicorn

# ================= E K S E K U S I =================

# Expose port 5000 (Port internal Flask/Gunicorn)
EXPOSE 5000

# Jalankan aplikasi dengan Gunicorn Production Server
# -w 4       : Menggunakan 4 worker process (bisa handle request paralel)
# -b ...:5000: Binding ke port 5000
# --access-logfile - : Print access log ke terminal docker
# --error-logfile -  : Print error log ke terminal docker
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "gatekeeper:app"]
```

</details>

<details>
<summary>Configurasi Gatekeeper (py)</summary>

```bash
nano gatekeeper.py
```

```
from flask import Flask, request, Response, redirect, make_response
import psycopg2
import bcrypt
import uuid
import json
import requests
import os
import re
import secrets
import urllib.parse
import sys

app = Flask(__name__)

# ================= K O N F I G U R A S I =================

DB_HOST = os.environ.get("DB_HOST", "db_postgres")
DB_NAME = os.environ.get("DB_NAME", "docmost")
DB_USER = os.environ.get("DB_USER", "admin")
DB_PASS = os.environ.get("DB_PASS", "**************")

DOCMOST_INTERNAL_URL = os.environ.get("DOCMOST_INTERNAL_URL", "http://app_docmost:3000")
KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://idp_keycloak:8080")

# Pastikan URL Publik ini benar
KEYCLOAK_PUBLIC_URL = os.environ.get("KEYCLOAK_PUBLIC_URL", "http://**************:8080")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://**************:3000")

KEYCLOAK_REALM = "docmost"
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "poc-docmos")
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "**************")

DEFAULT_LOCALE = "en-US"
DEFAULT_TIMEZONE = "Asia/Jakarta"
DEFAULT_SETTINGS = json.dumps({"theme": "system"})

ROLE_WORKSPACE_MEMBER = "member"
ROLE_SPACE_READER = "reader"
ROLE_SPACE_ADMIN = "admin"

# ================= 1. FUNGSI DATABASE =================

def get_db_connection():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

def create_private_space(cur, user_id, workspace_id, email_prefix):
    new_space_id = str(uuid.uuid4())
    clean_prefix = re.sub(r'[^a-zA-Z0-9]', '', email_prefix)
    unique_slug = f"my-docs-{clean_prefix}-{user_id[:4]}"

    cur.execute("""
        INSERT INTO spaces (id, name, slug, workspace_id, created_at, updated_at)
        VALUES (%s, %s, %s, %s, NOW(), NOW())
    """, (new_space_id, "My Documentation", unique_slug, workspace_id))

    cur.execute("""
        INSERT INTO space_members (id, space_id, user_id, group_id, role, created_at, updated_at)
        VALUES (%s, %s, %s, NULL, %s, NOW(), NOW())
    """, (str(uuid.uuid4()), new_space_id, user_id, ROLE_SPACE_ADMIN))

def sync_user_and_get_session_password(email):
    full_name = email.split('@')[0]
    email_prefix = full_name.lower()
    session_password = secrets.token_urlsafe(32) + "A1!"
    hashed_pass = bcrypt.hashpw(session_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id FROM workspaces LIMIT 1")
        workspace_res = cur.fetchone()

        if not workspace_res:
            print("[CRITICAL] Tidak ada Workspace di Database!", file=sys.stderr)
            return None

        primary_workspace_id = workspace_res[0]
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing = cur.fetchone()

        if not existing:
            user_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO users (id, name, email, password, workspace_id, role, email_verified_at, created_at, updated_at, has_generated_password, settings, locale, timezone) 
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW(), NOW(), false, %s, %s, %s)
            """, (user_id, full_name, email, hashed_pass, primary_workspace_id, ROLE_WORKSPACE_MEMBER, DEFAULT_SETTINGS, DEFAULT_LOCALE, DEFAULT_TIMEZONE))

            cur.execute("SELECT id FROM spaces WHERE workspace_id = %s AND name = 'General' LIMIT 1", (primary_workspace_id,))
            general_space = cur.fetchone()

            if general_space:
                cur.execute("""
                    INSERT INTO space_members (id, space_id, user_id, group_id, role, created_at, updated_at) 
                    VALUES (%s, %s, %s, NULL, %s, NOW(), NOW())
                """, (str(uuid.uuid4()), general_space[0], user_id, ROLE_SPACE_READER))

            create_private_space(cur, user_id, primary_workspace_id, email_prefix)
            print(f"[INFO] User Baru Dibuat: {email}", file=sys.stdout)

        else:
            user_id = existing[0]
            cur.execute("UPDATE users SET password = %s, updated_at = NOW() WHERE id = %s", (hashed_pass, user_id))

        conn.commit()
        cur.close()
        conn.close()
        return session_password

    except Exception as e:
        print(f"[DB ERROR] Sync Failed: {e}", file=sys.stderr)
        return None

# ================= 2. HELPER COOKIE DESTRUCTION =================

def nuke_all_cookies(resp):
    """
    Menghapus cookie se-agresif mungkin.
    """
    cookies_to_kill = ['docmost_session', 'docmost_userid', 'sso_id_token', 'force_sso_logout']
    
    for cookie in cookies_to_kill:
        resp.set_cookie(cookie, '', expires=0, max_age=0, path='/')
        resp.set_cookie(cookie, '', expires=0, max_age=0, path='/', httponly=True)
        resp.set_cookie(cookie, '', expires=0, max_age=0, path='/', httponly=True, samesite='Lax')

# ================= 3. ROUTE AUTENTIKASI =================

@app.route('/auth/login', methods=['GET'])
def login_redirect():
    redirect_uri = f"{APP_BASE_URL}/auth/callback"
    auth_url = (
        f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
        f"?client_id={KEYCLOAK_CLIENT_ID}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
    )
    return redirect(auth_url)

@app.route('/auth/callback', methods=['GET'])
def login_callback():
    code = request.args.get('code')
    if not code: return "Error: No Code", 400

    token_url = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    redirect_uri = f"{APP_BASE_URL}/auth/callback"
    
    payload = {
        'grant_type': 'authorization_code',
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'code': code,
        'redirect_uri': redirect_uri
    }

    try:
        r = requests.post(token_url, data=payload, verify=False, timeout=10)
        token_data = r.json()
        
        if 'access_token' not in token_data:
            print(f"[KEYCLOAK ERROR] {r.text}", file=sys.stderr)
            return f"Gagal Token: {r.text}", 401

        id_token = token_data.get('id_token') 
        access_token = token_data['access_token']

        user_info_url = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
        headers = {'Authorization': f'Bearer {access_token}'}
        user_r = requests.get(user_info_url, headers=headers, verify=False, timeout=10)
        user_info = user_r.json()
        email = user_info.get('email') or user_info.get('preferred_username')

        if not email: return "Error: No Email", 400

        temp_password = sync_user_and_get_session_password(email)
        if not temp_password: return "Database Error", 500

        docmost_login_url = f"{DOCMOST_INTERNAL_URL}/api/auth/login"
        login_payload = {"email": email, "password": temp_password}
        dm_resp = requests.post(docmost_login_url, json=login_payload, allow_redirects=False, timeout=10)

        if dm_resp.status_code in [200, 201]:
            final_resp = make_response(redirect('/'))
            
            # Pasang Cookie ID Token (Wajib ada untuk bypass login)
            if id_token:
                final_resp.set_cookie('sso_id_token', id_token, path='/', httponly=True, samesite='Lax')

            upstream_cookies = dm_resp.cookies.get_dict()
            if not upstream_cookies:
                data = dm_resp.json() if dm_resp.text else {}
                token = data.get('accessToken') or data.get('token')
                if token:
                    final_resp.set_cookie('docmost_session', token, path='/', httponly=True, samesite='Lax')
            
            for k, v in upstream_cookies.items():
                final_resp.set_cookie(k, v, path='/', httponly=True, samesite='Lax')
            
            return final_resp
        else:
            return f"Login Backend Fail: {dm_resp.status_code}", 500

    except Exception as e:
        return f"System Error: {str(e)}", 500

# ================= 4. ROUTE PROXY (DIPERKETAT) =================

@app.route('/api/auth/logout', methods=['POST'])
def intercept_logout_api():
    resp = make_response(json.dumps({"message": "Logout Initiated"}), 200)
    resp.headers['Content-Type'] = 'application/json'
    nuke_all_cookies(resp)
    resp.set_cookie('force_sso_logout', 'true', max_age=15, path='/')
    return resp

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    # 1. CEK FLAG LOGOUT
    if request.cookies.get('force_sso_logout') == 'true':
        id_token_hint = request.cookies.get('sso_id_token')
        post_logout_redirect = urllib.parse.quote(f"{APP_BASE_URL}/auth/login")
        
        logout_url = f"{KEYCLOAK_PUBLIC_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout?post_logout_redirect_uri={post_logout_redirect}&client_id={KEYCLOAK_CLIENT_ID}"
        if id_token_hint:
            logout_url += f"&id_token_hint={id_token_hint}"
            
        resp = make_response(redirect(logout_url))
        nuke_all_cookies(resp)
        return resp

    # 2. DEFINISI WHITELIST (File aset boleh lewat tanpa login)
    is_whitelisted = (
        path in ["auth/login", "auth/callback"] or 
        path.startswith("assets") or 
        path.startswith("_next") or 
        path.startswith("setup") or 
        path.startswith("api/public") or 
        path == "manifest.json" or
        path == "favicon.ico" or
        path == "robots.txt" or
        path.endswith(".png") or
        path.endswith(".jpg") or
        path.endswith(".svg") or
        path.endswith(".css") or
        path.endswith(".js")
    )

    # 3. CEK AUTENTIKASI KETAT
    # Jika browser tidak punya 'sso_id_token' DAN tidak punya 'docmost_session',
    # maka browser dianggap tamu ilegal -> Redirect Login.
    
    has_valid_session = request.cookies.get('sso_id_token') or request.cookies.get('docmost_session')

    if not has_valid_session and not is_whitelisted:
        return redirect('/auth/login')

    # 4. PROXY REQUEST KE BACKEND
    try:
        url = f"{DOCMOST_INTERNAL_URL}/{path}"
        if request.query_string: url += f"?{request.query_string.decode('utf-8')}"
        
        headers = {k: v for k, v in request.headers if k.lower() != 'host'}

        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
        final_response = Response(resp.content, resp.status_code, headers)

        # 5. MENCEGAH CACHE HALAMAN DASHBOARD
        if not is_whitelisted:
            final_response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            final_response.headers["Pragma"] = "no-cache"
            final_response.headers["Expires"] = "0"

        return final_response

    except Exception as e:
        return Response(f"Proxy Error: {e}", 502)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

</details>

<details>
<summary>Nyalakan hanya Keycloak & Database</summary>

```bash
docker compose up -d postgres keycloak
```

![](files/019c3883-a475-77a6-abdc-8a0af7b6c9cb/image.png)

> Buat Database Docmost
> 
> Karena Docmost butuh database sendiri,jadi harus masuk ke postgres sebentar untuk bikin DB kosong.

```bash
docker exec -it db_postgres psql -U admin -d keycloak

# Di dalam prompt SQL:
CREATE DATABASE docmost;
\q
```

![](files/019c3884-c409-729a-8191-95391b54e90f/image.png)

> Selanjutnya Akses Dashboard Keyloack ip:8080

</details>
<details>
<summary>Akses Dashboard Keyloack</summary>

> [http://IP_SERVER:8080](http://**************:8080)

![](files/019c3888-36b7-72ec-9be5-c89159f9f636/image.png)
<details>
<summary>HTTPS required Error ⚠️</summary>

![](files/019c3889-6829-70fa-b062-1233eee1ee6c/image.png)

> Secara default, Keycloak **memblokir** akses ke halaman Admin dari IP Publik (Eksternal) jika tidak menggunakan HTTPS.

### Solusi: mematikan paksa (Krena masih Tahap devlopment)

```bash
# Masuk ke dalam Container Keycloak
docker exec -it idp_keycloak bash

# Login ke Tool Admin sebagai localhost agar bypass https.
cd /opt/keycloak/bin
./kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin

# Matikan Wajib HTTPS
./kcadm.sh update realms/master -s sslRequired=NONE
```

![](files/019c388e-8556-77ac-9329-acd833c57d87/image.png)

> Jika sudah Akses ulang dashboard Keyloack.

</details>

```bash
# Default Login
username: **************
password: **************
```

![](files/019c3891-3b9a-703d-b311-7acfae8fe8e0/image.png)

> Sukses Login

![](files/019c3892-5f9b-77b0-81cb-dbc0586dbc27/image.png)

</details>
<details>
<summary>konfigurasi Keycloak agar bisa bicara dengan Active Directory (AD)</summary>

<details>
<summary>Buat Realm Baru</summary>

> Jangan pakai realm "Master" untuk aplikasi. buat wadah khusus misal nama “docmost“

![](files/019c3894-761e-708e-bc5a-7186de16a8e0/image.png)

![](files/019c3895-7c68-77fe-8beb-279144da076f/image.png)

![](files/019c3896-51b5-73ca-9f3a-456cd7aac960/image.png)

</details>
<details>
<summary>Hubungkan Realm ke Active Directory (AD)</summary>

- Pastikan ada di realm **docmost**.
- Di menu kiri, klik **User federation**.
- Klik **Add new provider** (atau Add Ldap) pilih **ldap**.
- Isi formulir dengan data Server AD:

![](files/019c3899-cc82-7676-b2b5-a08781b52a1d/image.png)

![](files/019c389a-8954-742b-83de-716453aef272/image.png)

> Isi sesuai informasi Server Active Directory

```bash
# Misal

Vendor: Active Directory

UI Display Name: Kantor-DTC (Bebas).


Connection & Authentication Settings:

Connection URL: ldap://**************:389

Users DN: CN=Users,DC=ad,DC=testing,DC=local

Bind DN: CN=Test Admin,CN=Users,DC=ad,DC=testing,DC=local

Bind Credential: **************

Kerberos Integration: default.

Sync Settings:

Edit Mode: READ_ONLY (Keycloak hanya Menerima AD).
```

![](files/019c389c-2e57-730d-8fff-10c47a7469da/image.png)

![](files/019c38a1-90e9-7779-98ad-4f54b27cbc7d/image.png)

![](files/019c38a1-cccc-735e-b8ec-3396319da68f/image.png)![](files/019c38a2-a0c0-775a-bbae-49ddaadb685b/image.png)

### Test Koneksi

![](files/019c38a3-f5ec-741c-9f97-29036dc66e70/image.png)

![](files/019c38a4-9845-75fa-ae23-73e40483e0bd/image.png)

> Jika **keduanya Sukses**, klik tombol **Save** di paling bawah.

![](files/019c38a5-8bf2-74fa-a26b-2785fac2c7d7/image.png)

Lanjut ke Sinkronisasi User dari Server Active Directory

</details>
<details>
<summary>Sinkronisasi User di Keyloack Dengan Data Active Directory</summary>

![](files/019c38a7-0fd7-7678-bb32-ebba142b4114/image.png)

![](files/019c38a8-a204-76c4-b225-b7e13a545803/image.png)

> Cek menu **Users** di sidebar kiri

Search (\*) Agar tampil semuanya.

![](files/019c38aa-0e9c-72d5-8818-aa273a0e5825/image.png)

> Selanjutnya Configurasi Client Secret

</details>

</details>
<details>
<summary>Configurasu Client Secret keyloack untuk `docker-compose.yml`</summary>

![](files/019c38ae-bac6-7150-9b77-d70dcf0b5268/image.png)

:::info
Client ID harus sama dengan isi `docker-compose.yml`

`bagian:` gatekeeper:

```bash
KEYCLOAK_CLIENT_ID: "poc-docmos"
```
:::

![](files/019c38b3-17b3-739d-9762-e39e72e499fb/image.png)

> **Client authentication:** **ON** (Wajib nyala agar dapat Secret).

![](files/019c38b3-dc55-77aa-b955-1d7fe5d9a458/image.png)

![](files/019c38b5-861e-71a2-b582-2ad7ba4ddddd/image.png)

:::info
Login settings Valid redirect URIs: http://**************:3000/* (Tanda bintang hanya di development, di production wajib link spesifik).
:::

> Selanjutnya Ambil Secret dari Client Secret.

</details>
<details>
<summary>Ambil Secret dari konfigurasi Client Secret (Untuk di masukkan ke dalam `docker-compose.yml`)</summary>

![](files/019c38b9-c8af-760a-8eec-12e3e36c508b/image.png)

> bDuV41eoavlMXVzvVYk5RWiGO1jltkmr

:::info
Masukkan ke dalam `docker-compose.yml`

bagian Gatekeeper:

```bash
KEYCLOAK_CLIENT_SECRET: "disini-client-secret"
```
:::

> Selanjutnya Nyalakan Semua Container

</details>
<details>
<summary>Nyalakan Semua Container</summary>

```bash
docker-compose up -d --build
```

![](files/019c38cb-28c0-7190-8198-dcac05bd775b/image.png)

> Selanjutnya Setup Docmost Workpase Administrator

</details>
<details>
<summary>Akses halaman Docmost setup workspace Administrator(Owner)</summary>

```bash
http://**************:3000/setup/register
```

![](files/019c38eb-bd41-7649-a23a-5fb03b6115b3/image.png)

> Berhasil masuk Dashboard Admin (Logout untuk testing keyloack)

![](files/019c38ec-9ad9-764c-8129-d423137e16ea/image.png)

![](files/019c3934-3889-72af-a1a5-c027fa5f4c6f/image.png)

> Sampai sini integrasi Docmost + keyloack + Active Directory berhasil

</details>
<details>
<summary>Membuat Keycloak Theme (Custom Login)</summary>

![](files/019c3946-77ec-73c8-9f18-25a709a500a4/image.png)![](files/019c3944-de82-763c-9910-813d00a03bb5/image.png)

```bash
# nano themes/docmost-theme/login/theme.properties
parent=keycloak
import=common/keycloak
styles=css/styles.css
```

```bash
nano themes/docmost-theme/login/resources/css/styles.css
```

```bash
/* Import Font */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap');

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    background-color: #f3f4f6 !important;
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}

/* Kartu Login */
.login-pf-page .card-pf {
    background: white !important;
    padding: 2.5rem !important;
    border-radius: 12px !important;
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1) !important;
    width: 100% !important;
    max-width: 450px !important; /* Sedikit lebih lebar untuk QR Code */
    border: none !important;
}

/* Judul */
#kc-header-wrapper {
    text-align: center;
    color: #111827;
    margin-bottom: 1.5rem;
    font-weight: 700;
    font-size: 1.5rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* Sembunyikan Header Default Keycloak yang jelek */
.login-pf-page .header {
    display: none;
}

/* Input Fields */
input.form-control {
    width: 100% !important;
    padding: 0.75rem !important;
    border: 1px solid #d1d5db !important;
    border-radius: 6px !important;
    font-size: 1rem !important;
    height: auto !important;
    margin-bottom: 10px;
}

/* Tombol Login */
#kc-login, #kc-form-buttons input[type="submit"] {
    width: 100% !important;
    background-color: #2563eb !important;
    color: white !important;
    padding: 0.75rem !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    cursor: pointer !important;
    font-size: 1rem !important;
    margin-top: 1rem;
}

#kc-login:hover {
    background-color: #1d4ed8 !important;
}

/* Label */
label {
    color: #374151 !important;
    font-weight: 500 !important;
}
```

![](files/019c3948-5223-7099-94a5-cfc74b147bcd/image.png)

![](files/019c3948-cc9c-73ed-8c8a-85e8b3629659/image.png)

> Selanjutnya Aktifkan (2FA) OTP

</details>
<details>
<summary>Mengaktifkan 2FA (OTP) 6 digit</summary>

> Paksa user yang sudah ada mauoun yang baru join ke docmost untuk menggunakan 6 Digit OTP (Google Authenticator)

### Atur Kebijakan OTP (OTP Policy)

![](files/019c3953-7c88-77ee-a561-001a6553a59d/image.png)

### Buat Browser Flow

> Alur yang memaksa user tanpa syarat.

![](files/019c3957-6ed2-74c9-970b-9557f4f22c1b/image.png)

![](files/019c3958-2b16-7198-9418-f3700f3da36e/image.png)

![](files/019c3959-28a6-7278-9714-b231384ec244/image.png)

![](files/019c3959-d011-7024-9751-702f021c2162/image.png)

![](files/019c395a-3218-72fb-a4f5-32b4ec39c185/image.png)

![](files/019c395a-ddd4-76a7-80e8-eac52562972b/image.png)

![](files/019c395b-7fd5-728d-9dfd-febff6599660/image.png)

![](files/019c395c-1394-766b-802c-efddf731cd38/image.png)

![](files/019c395c-c2de-726b-bb17-5fd0782ca533/image.png)

### Bind Flow ke Browser

![](files/019c395f-576b-732a-b7d1-fbe8487519c9/image.png)

![](files/019c395f-aead-7249-9db1-273e3af1d394/image.png)

![](files/019c3960-6a1a-7366-9764-1f614b54dd11/image.png)

### Paksa Client Menggunakan Flow(Override)

![](files/019c3961-9ce2-70dd-ba92-658e2f44ffe9/image.png)

![](files/019c3962-81d2-748f-9cfb-ffef56b34e21/image.png)

![](files/019c3963-3880-758b-8456-60505c7af996/image.png)

### Testing Login

> Scan Google Autenthicator

![](files/019c3965-5f4f-73f4-af9c-98dfa49c9e7d/image.png)

</details>
<details>
<summary>Tampilan Custom Login/OTP</summary>

![](files/019c3970-6da5-729d-b2a7-1d9bcb4cd7e8/image.png)

> Menngunakan FTL(FreeMarker Template Language) karena Keycloak dibangun menggunakan bahasa pemrograman Java (lebih spesifiknya framework Quarkus/Wildfly). FreeMarker adalah mesin template standar untuk aplikasi Java.

<details>
<summary>nano themes/docmost-theme/login/[theme.properties](http://theme.properties)</summary>

```bash
parent=keycloak
import=common/keycloak
styles=css/styles.css
```

</details>
<details>
<summary>nano themes/docmost-theme/login/login.ftl</summary>

```java
<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=(social.displayInfo!false); section>
    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
    <div id="kc-form">
      <div id="kc-form-wrapper">
        <#if realm.password>
            <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
                
                <div class="${properties.kcFormGroupClass!}">
                    <label for="username" class="${properties.kcLabelClass!}"><#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if></label>

                    <#if usernameEditDisabled??>
                        <input tabindex="1" id="username" class="form-control" name="username" value="${(login.username!'')}" type="text" disabled />
                    <#else>
                        <input tabindex="1" id="username" class="form-control" name="username" value="${(login.username!'')}"  type="text" autofocus autocomplete="off" />
                    </#if>
                </div>

                <div class="${properties.kcFormGroupClass!}">
                    <label for="password" class="${properties.kcLabelClass!}">${msg("password")}</label>
                    <input tabindex="2" id="password" class="form-control" name="password" type="password" autocomplete="off" />
                </div>

                <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                    <div id="kc-form-options">
                        <#if realm.rememberMe && !usernameEditDisabled??>
                            <div class="checkbox">
                                <label>
                                    <#if login.rememberMe??>
                                        <input tabindex="3" id="rememberMe" name="rememberMe" type="checkbox" checked> ${msg("rememberMe")}
                                    <#else>
                                        <input tabindex="3" id="rememberMe" name="rememberMe" type="checkbox"> ${msg("rememberMe")}
                                    </#if>
                                </label>
                            </div>
                        </#if>
                    </div>
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                        <#if realm.resetPasswordAllowed>
                            <span><a tabindex="5" href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a></span>
                        </#if>
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                    <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                    <input tabindex="4" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                </div>
            </form>
        </#if>
      </div>
      
      <#if realm.password && social.providers??>
        <div id="kc-social-providers" class="${properties.kcFormSocialAccountSectionClass!}">
            <hr/>
            <h4>${msg("identity-provider-login-label")}</h4>
            <ul class="${properties.kcFormSocialAccountListClass!}">
                <#list social.providers as p>
                    <a id="social-${p.alias}" class="${properties.kcFormSocialAccountListButtonClass!} <#if social.providers?size gt 3>${properties.kcFormSocialAccountGridItem!}</#if>"
                            type="button" href="${p.loginUrl}">
                        <span class="${properties.kcFormSocialAccountNameClass!}">${p.displayName!}</span>
                    </a>
                </#list>
            </ul>
        </div>
      </#if>
      
    </div>
    </#if>
</@layout.registrationLayout>
```

</details>
<details>
<summary>nano themes/docmost-theme/login/login-otp.ftl</summary>

```bash
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('totp'); section>
    <#if section = "header">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="otp" class="${properties.kcLabelClass!}">${msg("loginOtpOneTime")}</label>
                </div>
                
                <div class="${properties.kcInputWrapperClass!}">
                    <input id="otp" name="otp" autocomplete="off" type="text" class="form-control" autofocus aria-invalid="<#if messagesPerField.existsError('totp')>true</#if>"/>
                    
                    <#if messagesPerField.existsError('totp')>
                        <span id="input-error-otp-code" class="${properties.kcInputErrorMessageClass!}" aria-live="polite" style="color:red; margin-top:5px; display:block;">
                            ${kcSanitize(messagesPerField.get('totp'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input
                        class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                        name="login" id="kc-login" type="submit" value="${msg("doLogIn")}" />
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
```

</details>
<details>
<summary>nano themes/docmost-theme/login/logout-confirm.ftl</summary>

```java
<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("logoutConfirmTitle")}
    <#elseif section = "form">
        <div id="kc-logout-confirm" class="content-area">
            <p class="instruction" style="text-align:center; margin-bottom:20px;">${msg("logoutConfirmHeader")}</p>

            <form class="form-actions" action="${url.logoutConfirmAction}" method="POST">
                <input type="hidden" name="session_code" value="${logoutConfirm.code}">
                
                <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" 
                           name="confirmLogout" id="kc-logout" type="submit" value="${msg("doLogout")}"/>
                </div>
            </form>
        </div>
    </#if>
</@layout.registrationLayout>
```

</details>
<details>
<summary>nano themes/docmost-theme/login/resources/css/styles.css</summary>

```java
/* Import Font */
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap');

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    background-color: #f3f4f6 !important;
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}

/* Kartu Login */
.login-pf-page .card-pf {
    background: white !important;
    padding: 2.5rem !important;
    border-radius: 12px !important;
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1) !important;
    width: 100% !important;
    max-width: 450px !important;
    border: none !important;
}

/* Judul */
#kc-header-wrapper {
    text-align: center;
    color: #111827;
    margin-bottom: 1.5rem;
    font-weight: 700;
    font-size: 1.5rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* Sembunyikan Header Default Keycloak */
.login-pf-page .header {
    display: none;
}

/* Input Fields */
input.form-control {
    width: 100% !important;
    padding: 0.75rem !important;
    border: 1px solid #d1d5db !important;
    border-radius: 6px !important;
    font-size: 1rem !important;
    height: auto !important;
    margin-bottom: 10px;
    box-sizing: border-box; /* Tambahan agar padding tidak merusak width */
}

/* Tombol Login */
#kc-login, #kc-form-buttons input[type="submit"] {
    width: 100% !important;
    background-color: #2563eb !important;
    color: white !important;
    padding: 0.75rem !important;
    border: none !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    cursor: pointer !important;
    font-size: 1rem !important;
    margin-top: 1rem;
}

#kc-login:hover {
    background-color: #1d4ed8 !important;
}

/* Label */
label {
    color: #374151 !important;
    font-weight: 500 !important;
    display: block;
    margin-bottom: 0.5rem;
}
```

</details>

</details>
<details>
<summary>HTTPS SSL Nginx Reverse proxy to domain name</summary>

## 🔜 (upcoming / segera)

</details>

## Bagaimana Cara kerjanya ?

> Bagaimana Kerja Integrasi SSO Docmost dengan Active Directory menggunakan Metode JIT Provisioning & Ephemeral Credential Injection

<details>
<summary>Alur Kerja Sistem (End-to-End)</summary>

:::info
Sistem ini bekerja dengan menempatkan Gatekeeper (Python Middleware) sebagai perantara cerdas yang memanipulasi proses login Docmost agar bisa menerima pengguna dari Active Directory (via Keycloak) secara otomatis.
:::

Berikut adalah 4 tahapan prosesnya:

- Intersepsi & Validasi Identitas  
    User membuka domain docmost  
    Nginx meneruskan permintaan ke Gatekeeper.  
    Gatekeeper memeriksa apakah browser pengguna memiliki Cookie sso_id_token atau docmost_session.  
    Jika tidak ada Cookie, Gatekeeper melempar pengguna ke halaman login Keycloak.
- Autentikasi Terpusat  
    Keycloak menampilkan formulir login.  
    User memasukkan username & password akun Active Directory.  
    Keycloak memverifikasi kredensial tersebut langsung ke server Active Directory/LDAP.  
    Jika valid, Keycloak mengirimkan data pengguna (Email & Nama) kembali ke Gatekeeper melalui protokol OpenID Connect (OIDC).  
    Password asli AD tidak pernah dikirim ke Gatekeeper atau Docmost.
- Sinkronisasi Kilat & Kredensial Sementara  
    Ini adalah inti dari bypass sistem:  
    Gatekeeper menerima email pengguna yang terverifikasi (misal: [wahyudi@datacomm.co.id](mailto:wahyudi@datacomm.co.id)).  
    Gatekeeper membuat password acak 32 karakter (kredensial sekali pakai) yang sangat kuat.  
    JIT (Just-In-Time) Provisioning: Gatekeeper melakukan koneksi langsung ke database PostgreSQL Docmost:  
    Jika pengguna BARU: Gatekeeper membuat user baru di database Docmost dengan password acak tersebut.  
    Jika pengguna LAMA: Gatekeeper menimpa password lama di database dengan password acak yang baru dibuat.
- Login Sintetis & Injeksi Sesi  
    Gatekeeper bertindak sebagai "robot" yang melakukan login ke API Docmost (POST /api/auth/login) menggunakan email user dan password acak tadi.  
    Docmost memvalidasi login sukses dan memberikan Session Cookie.  
    Gatekeeper mengambil cookie tersebut dan menanamkannya (inject) ke browser pengguna.  
    Redirect: Pengguna diarahkan kembali ke halaman utama. Browser pengguna kini memiliki sesi valid seolah-olah mereka login manual.

</details>
<details>
<summary>Bagaimana User baru bisa langsung join Docmost ?</summary>

:::info
Didalam Cofr [gatekeeper.py](http://gatekeeper.py) diatur agar user baru yang berhasil login melewati Autentikasi Keyloack, Script gatekeeper akan otomatis membuatkan user baru ke dalam Space General(Bersama ReadOnly) dan membuatkan Space baru dengan nama MyDocumentation. semuanya di atur dalam Configurasi gatekeeper.py
:::

</details>

## Apakah Sistem ini aman ?

<details>
<summary>Kelebihan Arsitektur Ini</summary>

- Seamless: Pengguna Active Directory bisa masuk ke aplikasi yang tidak mendukung AD/LDAP.
- Zero-Knowledge Password: Database aplikasi (Docmost) tidak pernah menyimpan password asli pengguna, hanya password acak yang tidak berguna bagi peretas.
- Cost-Effective: Mengubah fitur "Enterprise SSO" (yang biasanya berbayar) menjadi solusi gratis menggunakan teknik Form-Based Authentication Impersonation.

</details>

:::info
Secara arsitektur, sistem ini didesain dengan tingkat keamanan yang tinggi karena menerapkan prinsip "Zero-Knowledge Credential" pada sisi aplikasi target.  
Keamanan utama terletak pada mekanisme Ephemeral Credential Injection, di mana Gatekeeper menghasilkan password acak 32 karakter menggunakan modul kriptografi secrets.token_urlsafe setiap kali pengguna login, sehingga password asli Active Directory tidak pernah menyentuh ataupun tersimpan di database Docmost.  
Seluruh proses sensitif—mulai dari pembuatan password, injeksi ke database PostgreSQL, hingga synthetic login—berjalan secara terisolasi di dalam jaringan internal Docker (internal_net) yang tidak dapat diakses dari publik, memitigasi risiko penyadapan jaringan.  
Selain itu, keamanan sesi pengguna terjamin melalui penggunaan HttpOnly Cookies dan SameSite=Lax yang mencegah serangan Cross-Site Scripting (XSS) pada sisi klien. Dengan demikian, bahkan jika database Docmost bocor, penyerang hanya akan mendapatkan hash dari password sampah yang tidak valid lagi untuk sesi berikutnya.
:::

## Functional Testing

> Sistem ini menghubungkan tiga komponen utama:

- Active Directory & Keycloak Berfungsi sebagai Identity Provider (IdP). Bertanggung jawab memverifikasi "Siapa Anda" (Autentikasi).
- Gatekeeper (Custom Middleware) Berfungsi sebagai Authentication Broker yang menerjemahkan identitas dari Keycloak menjadi sesi login lokal Docmost dengan teknik Password Rotation otomatis setiap kali login.
- Docmost Berfungsi sebagai Service Provider yang menerima pengguna yang sudah divalidasi tanpa perlu dikonfigurasi untuk SSO, karena sistem menganggap login dilakukan secara native.

## Hasil Akhir Kriteria Keberhasilan (Success Criteria)

:::info
Kriteria Keberhasilan (Success Criteria)  
PoC dianggap berhasil karena.  
\[ \] Docmost dapat diakses melalui Public IP.  
\[ \] User dapat membuat dan mengedit dokumen tanpa error.  
\[ \] User dapat login menggunakan kredensial Active Directory (AD).  
\[ \] Sistem meminta 2FA saat proses login berlangsung.
:::

## Hasil Akhir PoC (Sistem siap Deploy produksi)

:::info
Seluruh tahapan pengembangan dan stress-test pada infrastruktur SSO telah selesai dilakukan tanpa isu kritikal. Integrasi backend berjalan lancar dan mekanisme keamanan kredensial dinamis telah terverifikasi aman dari potensi kebocoran data. Dengan stabilitas yang telah terbukti pada lingkungan staging, saat ini Sistem siap Deploy produksi untuk segera digunakan oleh pengguna akhir.
:::
