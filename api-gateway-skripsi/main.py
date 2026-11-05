import os
import json
import base64
from datetime import datetime
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import httpx
from pydantic import BaseModel
import sqlite3

load_dotenv()

app = FastAPI(
    title="API Gateway Skripsi",
    description="Middleware Omnichannel Berbasis RBAC untuk Magento dan Keycloak",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://frontend-sso.test", 
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://localhost",
        "http://127.0.0.1:65364"
    ],
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

MAGENTO_BASE_URL = os.getenv("MAGENTO_BASE_URL")
MAGENTO_INTEGRATION_TOKEN = os.getenv("MAGENTO_INTEGRATION_TOKEN")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID_SIMULASI = os.getenv("TELEGRAM_CHAT_ID") 
KEYCLOAK_USERINFO_URL = "http://localhost:8080/realms/ecommerce-sso/protocol/openid-connect/userinfo"

security = HTTPBearer()

# ==========================================
# INISIALISASI BASIS DATA MIKRO (SQLITE)
# ==========================================
def init_db():
    conn = sqlite3.connect("ecommerce_sso.db")
    cursor = conn.cursor()
    # Tabel 1: Menyimpan preferensi langganan pelanggan
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telegram_subscribers (
            email TEXT PRIMARY KEY,
            chat_id TEXT,
            is_subscribed BOOLEAN DEFAULT 1
        )
    """)
    # Tabel 2: Menyimpan riwayat eksekusi broadcast beserta status/alasan gagal
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS broadcast_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            admin_email TEXT,
            sku TEXT,
            product_name TEXT,
            discount TEXT,
            message TEXT,
            recipient_count INTEGER,
            status_note TEXT
        )
    """)
    # Auto-migration: Tambahkan kolom status_note jika tabel lama belum memilikinya
    try:
        cursor.execute(
            "ALTER TABLE broadcast_history ADD COLUMN status_note TEXT DEFAULT 'BERHASIL: Terkirim ke pelanggan aktif.'"
        )
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    init_db()

# ==========================================
# FUNGSI KEAMANAN, INTROSPEKSI & RBAC
# ==========================================
def extract_roles_from_jwt(token: str) -> list:
    """Mengekstrak daftar role dari payload JWT Keycloak (realm_access.roles)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return []
        payload_b64 = parts[1]
        padding = "=" * ((4 - len(payload_b64) % 4) % 4)
        decoded_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload_data = json.loads(decoded_bytes.decode("utf-8"))
        return payload_data.get("realm_access", {}).get("roles", [])
    except Exception:
        return []

async def verify_token_with_keycloak(token: str):
    """Memvalidasi keaktifan token secara real-time ke endpoint /userinfo Keycloak."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get(KEYCLOAK_USERINFO_URL, headers=headers)
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Akses Ditolak! KTP Digital (JWT) tidak valid atau sudah kedaluwarsa di Keycloak."
            )
        return response.json()

async def verify_jwt_and_swap_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Memvalidasi JWT lalu menukarnya dengan Integration Token Magento (Token Swapping)."""
    jwt_keycloak = credentials.credentials
    if not jwt_keycloak:
        raise HTTPException(status_code=401, detail="KTP Digital (JWT) tidak ditemukan!")
    await verify_token_with_keycloak(jwt_keycloak)
    return MAGENTO_INTEGRATION_TOKEN

async def verify_admin_role(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency RBAC: Memastikan pengguna memiliki token aktif DAN ber-role 'admin'."""
    token_keycloak = credentials.credentials
    user_info = await verify_token_with_keycloak(token_keycloak)
    roles = extract_roles_from_jwt(token_keycloak)
    
    if "admin" not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Akses Ditolak (403 Forbidden)! Rute ini hanya dapat diakses oleh Administrator."
        )
    return user_info

# ==========================================
# ENDPOINT 1: AUTENTIKASI & SINKRONISASI
# ==========================================
@app.post("/api/v1/auth")
async def authenticate_and_sync(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_keycloak = credentials.credentials
    user_info = await verify_token_with_keycloak(token_keycloak)
    roles = extract_roles_from_jwt(token_keycloak)
    
    email = user_info.get("email") or user_info.get("preferred_username")
    first_name = user_info.get("given_name", "User")
    last_name = user_info.get("family_name", "Keycloak")

    # 1. Jika yang login memiliki role 'admin', arahkan ke mode Admin tanpa daftar ke Magento
    if "admin" in roles:
        return {
            "status": "ADMIN_AUTHENTICATED",
            "role": "admin",
            "email": email,
            "message": "Selamat datang di Dasbor Administrator."
        }

    # 2. Jika Pelanggan biasa, wajib memiliki email untuk sinkronisasi Magento & SQLite
    if not email:
        raise HTTPException(status_code=400, detail="Email tidak ditemukan dari Keycloak")

    conn = sqlite3.connect("ecommerce_sso.db")
    cursor = conn.cursor()
    cursor.execute("SELECT is_subscribed FROM telegram_subscribers WHERE email = ?", (email,))
    row = cursor.fetchone()

    is_subscribed = 1
    if row is None:
        cursor.execute(
            "INSERT INTO telegram_subscribers (email, chat_id, is_subscribed) VALUES (?, ?, 1)",
            (email, TELEGRAM_CHAT_ID_SIMULASI)
        )
        conn.commit()
    else:
        is_subscribed = row[0]
    conn.close()

    headers = {
        "Authorization": f"Bearer {MAGENTO_INTEGRATION_TOKEN}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient(timeout=90.0) as client:
        search_url = (
            f"{MAGENTO_BASE_URL}/customers/search?"
            f"searchCriteria[filter_groups][0][filters][0][field]=email&"
            f"searchCriteria[filter_groups][0][filters][0][value]={email}&"
            f"searchCriteria[filter_groups][0][filters][0][condition_type]=eq"
        )
        try:
            check_response = await client.get(search_url, headers=headers)
            check_response.raise_for_status()
            search_result = check_response.json()
            
            if search_result.get("total_count", 0) > 0:
                return {
                    "status": "EXISTING_USER",
                    "role": "customer",
                    "message": "Pelanggan terdaftar di Magento.",
                    "is_subscribed": is_subscribed
                }
            else:
                new_customer_payload = {
                    "customer": {"email": email, "firstname": first_name, "lastname": last_name}
                }
                create_response = await client.post(
                    f"{MAGENTO_BASE_URL}/customers", headers=headers, json=new_customer_payload
                )
                create_response.raise_for_status()
                return {
                    "status": "NEW_USER_CREATED",
                    "role": "customer",
                    "message": "Pelanggan didaftarkan ke Magento.",
                    "is_subscribed": is_subscribed
                }
                
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error Magento: {e.response.text}")

# ==========================================
# ENDPOINT 2: KATALOG PRODUK (BFF PATTERN)
# ==========================================
@app.get("/api/v1/products")
async def get_products(magento_token: str = Depends(verify_jwt_and_swap_token)):
    headers = {
        "Authorization": f"Bearer {magento_token}",
        "Content-Type": "application/json"
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.get(f"{MAGENTO_BASE_URL}/products?searchCriteria[pageSize]=50", headers=headers)
            response.raise_for_status() 
            raw_data = response.json()
            clean_products = []
            
            MEDIA_BASE_URL = f"{MAGENTO_BASE_URL.replace('/rest/V1', '')}/media/catalog/product"
            STORE_FRONT_URL = MAGENTO_BASE_URL.replace('/rest/V1', '')
            
            for item in raw_data.get("items", []):
                sku = item.get("sku")
                name = item.get("name")
                price = item.get("price")
                image_path = ""
                url_key = ""
                
                for attr in item.get("custom_attributes", []):
                    if attr.get("attribute_code") == "image":
                        image_path = attr.get("value")
                    elif attr.get("attribute_code") == "url_key":
                        url_key = attr.get("value")
                
                full_image_url = f"{MEDIA_BASE_URL}{image_path}" if image_path else None
                full_product_link = f"{STORE_FRONT_URL}/{url_key}.html" if url_key else None
                
                clean_products.append({
                    "sku": sku, "name": name, "price": price,
                    "image_url": full_image_url, "product_link": full_product_link
                })
                
            return {"status": "SUCCESS", "data": clean_products}
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=e.response.status_code, detail="Magento menolak permintaan Gateway.")

# ==========================================
# ENDPOINT 3: MANAJEMEN LANGGANAN (RESTFUL)
# ==========================================
@app.post("/api/v1/marketing/subscribe")
async def subscribe_promo(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_keycloak = credentials.credentials
    user_info = await verify_token_with_keycloak(token_keycloak)
    email = user_info.get("email")

    conn = sqlite3.connect("ecommerce_sso.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE telegram_subscribers SET is_subscribed = 1 WHERE email = ?", (email,))
    conn.commit()
    row_count = cursor.rowcount
    conn.close()

    if row_count == 0:
        raise HTTPException(status_code=404, detail="Data pelanggan tidak ditemukan.")
    
    return {"status": "SUCCESS", "message": "Anda telah mengaktifkan kembali promo Telegram!"}

@app.delete("/api/v1/marketing/subscribe")
async def unsubscribe_promo(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token_keycloak = credentials.credentials
    user_info = await verify_token_with_keycloak(token_keycloak)
    email = user_info.get("email")

    conn = sqlite3.connect("ecommerce_sso.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE telegram_subscribers SET is_subscribed = 0 WHERE email = ?", (email,))
    conn.commit()
    row_count = cursor.rowcount
    conn.close()

    if row_count == 0:
        raise HTTPException(status_code=404, detail="Data pelanggan tidak ditemukan.")
    
    return {"status": "SUCCESS", "message": "Anda telah sukses berhenti berlangganan promo Telegram."}

# ==========================================
# ENDPOINT 4: BROADCAST & RIWAYAT (ADMIN RBAC)
# ==========================================
class PromoMessage(BaseModel):
    sku: str
    discount: str
    message: str

@app.post("/api/v1/marketing/broadcast")
async def broadcast_promo(promo: PromoMessage, admin_info: dict = Depends(verify_admin_role)):
    admin_email = admin_info.get("email") or admin_info.get("preferred_username", "admin")
    headers = {"Authorization": f"Bearer {MAGENTO_INTEGRATION_TOKEN}", "Content-Type": "application/json"}
    product_api_url = f"{MAGENTO_BASE_URL}/products/{promo.sku}"
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            magento_resp = await client.get(product_api_url, headers=headers)
            magento_resp.raise_for_status()
            product_data = magento_resp.json()
            product_name = product_data.get("name", promo.sku)
            
            FRONTEND_BASE_URL = "http://frontend-sso.test/index.html"
            product_link = f"{FRONTEND_BASE_URL}?sku={promo.sku}"
            
        except httpx.HTTPStatusError:
            raise HTTPException(status_code=404, detail=f"Produk dengan SKU {promo.sku} tidak ditemukan.")

    text_message = (
        f"🎉 *PROMO SPESIAL UNTUKMU!* 🎉\n\n"
        f"🛍️ *Produk:* [{product_name}]({product_link})\n"
        f"💸 *Diskon:* {promo.discount}\n\n"
        f"💬 {promo.message}\n\n"
        f"Yuk, klik nama produk di atas untuk belanja!"
    )

    conn = sqlite3.connect("ecommerce_sso.db")
    cursor = conn.cursor()
    cursor.execute("SELECT chat_id FROM telegram_subscribers WHERE is_subscribed = 1")
    subscribers = cursor.fetchall()
    timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Kondisi 1: Gagal karena seluruh pelanggan berstatus unsubscribe (0 penerima aktif)
    if not subscribers:
        status_note = "GAGAL: Tidak ada pelanggan berlangganan aktif (0 subscriber)."
        cursor.execute("""
            INSERT INTO broadcast_history (timestamp, admin_email, sku, product_name, discount, message, recipient_count, status_note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (timestamp_now, admin_email, promo.sku, product_name, promo.discount, promo.message, 0, status_note))
        conn.commit()
        conn.close()
        return {
            "status": "FAILED",
            "message": f"Broadcast dibatalkan: {status_note}"
        }

    # Kondisi 2 & 3: Proses pengiriman ke API Telegram dan pelacakan alasan gagal
    telegram_api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    success_count = 0
    fail_count = 0
    error_reasons = []
    
    async with httpx.AsyncClient(timeout=10.0) as tg_client:
        for sub in subscribers:
            payload = {"chat_id": sub[0], "text": text_message, "parse_mode": "Markdown"}
            try:
                resp = await tg_client.post(telegram_api_url, json=payload)
                if resp.status_code == 200:
                    success_count += 1
                else:
                    fail_count += 1
                    try:
                        err_desc = resp.json().get("description", f"HTTP {resp.status_code}")
                    except Exception:
                        err_desc = f"Telegram Error HTTP {resp.status_code}"
                    if err_desc not in error_reasons:
                        error_reasons.append(err_desc)
            except Exception:
                fail_count += 1
                net_err = "Koneksi ke server Telegram terputus (Timeout)"
                if net_err not in error_reasons:
                    error_reasons.append(net_err)

    if success_count > 0 and fail_count == 0:
        overall_status = "SUCCESS"
        status_note = "BERHASIL: Terkirim ke seluruh pelanggan aktif."
        resp_msg = f"Promo produk '{product_name}' berhasil dikirim ke {success_count} pelanggan dan dicatat ke riwayat!"
    elif success_count > 0 and fail_count > 0:
        overall_status = "PARTIAL"
        reason_str = "; ".join(error_reasons)
        status_note = f"PARSIAL ({fail_count} gagal): {reason_str}"
        resp_msg = f"Promo terkirim sebagian ({success_count} sukses, {fail_count} gagal: {reason_str})."
    else:
        overall_status = "FAILED"
        reason_str = "; ".join(error_reasons) if error_reasons else "Gagal menghubungi API Telegram"
        status_note = f"GAGAL: {reason_str}"
        resp_msg = f"Broadcast gagal dikirim ({reason_str}). Alasan kegagalan telah dicatat ke riwayat."

    # Simpan catatan eksekusi beserta status_note ke tabel broadcast_history
    cursor.execute("""
        INSERT INTO broadcast_history (timestamp, admin_email, sku, product_name, discount, message, recipient_count, status_note)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp_now, admin_email, promo.sku, product_name, promo.discount, promo.message, success_count, status_note))
    conn.commit()
    conn.close()

    return {
        "status": overall_status,
        "message": resp_msg,
        "status_note": status_note
    }

@app.get("/api/v1/marketing/broadcast")
async def get_broadcast_history(admin_info: dict = Depends(verify_admin_role)):
    conn = sqlite3.connect("ecommerce_sso.db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, admin_email, sku, product_name, discount, message, recipient_count, status_note
        FROM broadcast_history
        ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    history_list = []
    for r in rows:
        history_list.append({
            "id": r[0],
            "timestamp": r[1],
            "admin_email": r[2],
            "sku": r[3],
            "product_name": r[4],
            "discount": r[5],
            "message": r[6],
            "recipient_count": r[7],
            "status_note": r[8] or "BERHASIL: Terkirim ke pelanggan aktif."
        })

    return {"status": "SUCCESS", "data": history_list}