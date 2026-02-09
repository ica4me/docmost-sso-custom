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

# 1. Keamanan Flask (Secret Key)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# 2. Database
DB_HOST = os.environ.get("DB_HOST", "db_postgres")
DB_NAME = os.environ.get("DB_NAME", "docmost")
DB_USER = os.environ.get("DB_USER", "admin")
# Diambil dari ENV
DB_PASS = os.environ.get("DB_PASS")

# 3. URLs
DOCMOST_INTERNAL_URL = os.environ.get("DOCMOST_INTERNAL_URL", "http://app_docmost:3000")
KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://idp_keycloak:8080")
KEYCLOAK_PUBLIC_URL = os.environ.get("KEYCLOAK_PUBLIC_URL")
APP_BASE_URL = os.environ.get("APP_BASE_URL")

# 4. Keycloak Identity
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "docmost")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID")
KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET")

# 5. Nama Cookie (Dinamis agar tahan update versi)
COOKIE_SESSION_NAME = os.environ.get("COOKIE_SESSION_NAME", "docmost_session")
COOKIE_USERID_NAME = os.environ.get("COOKIE_USERID_NAME", "docmost_userid")
COOKIE_SSO_TOKEN = os.environ.get("COOKIE_SSO_TOKEN", "sso_id_token")

# 6. Default Settings
DEFAULT_SPACE_NAME = os.environ.get("DEFAULT_SPACE_NAME", "My Documentation")
DEFAULT_LOCALE = os.environ.get("DEFAULT_LOCALE", "en-US")
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

    # DEFAULT_SPACE_NAME dari .env
    cur.execute("""
        INSERT INTO spaces (id, name, slug, workspace_id, created_at, updated_at)
        VALUES (%s, %s, %s, %s, NOW(), NOW())
    """, (new_space_id, DEFAULT_SPACE_NAME, unique_slug, workspace_id))

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
    # List cookie diambil dari variabel global
    cookies_to_kill = [COOKIE_SESSION_NAME, COOKIE_USERID_NAME, COOKIE_SSO_TOKEN, 'force_sso_logout']
    
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
            
            # Pasang Cookie ID Token (Gunakan Variabel)
            if id_token:
                final_resp.set_cookie(COOKIE_SSO_TOKEN, id_token, path='/', httponly=True, samesite='Lax')

            upstream_cookies = dm_resp.cookies.get_dict()
            if not upstream_cookies:
                data = dm_resp.json() if dm_resp.text else {}
                token = data.get('accessToken') or data.get('token')
                if token:
                    # Gunakan nama cookie dinamis
                    final_resp.set_cookie(COOKIE_SESSION_NAME, token, path='/', httponly=True, samesite='Lax')
            
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
        # Gunakan variabel COOKIE_SSO_TOKEN
        id_token_hint = request.cookies.get(COOKIE_SSO_TOKEN)
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
    # Menggunakan nama cookie dinamis
    has_valid_session = request.cookies.get(COOKIE_SSO_TOKEN) or request.cookies.get(COOKIE_SESSION_NAME)

    if not has_valid_session and not is_whitelisted:
        # User mencoba akses halaman utama tanpa tiket login yang valid
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
