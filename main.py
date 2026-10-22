import os
import secrets
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

DATABASE_URL = os.getenv("DATABASE_URL", "")
ADMIN_PIN = os.getenv("ADMIN_PIN", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")

if not DATABASE_URL:
    raise RuntimeError("Chýba DATABASE_URL. Nastav ho v prostredí servera.")
if not ADMIN_PIN:
    raise RuntimeError("Chýba ADMIN_PIN. Nastav ho v prostredí servera.")
if len(SESSION_SECRET) < 32:
    raise RuntimeError("Nastav SESSION_SECRET na náhodný reťazec s aspoň 32 znakmi.")

# Render niekedy poskytuje postgres:// URL; psycopg očakáva postgresql://.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

app = FastAPI(title="Školský e-shop")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=os.getenv("COOKIE_SECURE", "true").lower() == "true",
    session_cookie="eshop_session",
    max_age=60 * 60 * 4,
)
templates = Jinja2Templates(directory="templates")


def db_connect():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10)


def init_db():
    defaults = [
        (1, "Jablko", Decimal("0.50"), 10),
        (2, "Banán", Decimal("0.45"), 10),
        (3, "Mrkva", Decimal("0.30"), 10),
        (4, "Zemiak", Decimal("0.25"), 15),
        (5, "Mlieko", Decimal("1.20"), 5),
    ]
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                price NUMERIC(10,2) NOT NULL CHECK (price >= 0),
                stock INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id BIGSERIAL PRIMARY KEY,
                total NUMERIC(10,2) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS order_items (
                id BIGSERIAL PRIMARY KEY,
                order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
                product_id INTEGER NOT NULL,
                product_name VARCHAR(100) NOT NULL,
                unit_price NUMERIC(10,2) NOT NULL,
                quantity INTEGER NOT NULL CHECK (quantity > 0)
            )
        """)
        for product in defaults:
            conn.execute(
                """INSERT INTO products (id, name, price, stock)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (id) DO NOTHING""",
                product,
            )


@app.on_event("startup")
def startup():
    init_db()


class LoginBody(BaseModel):
    pin: str = Field(min_length=1, max_length=100)


class StockBody(BaseModel):
    amount: int = Field(ge=1, le=10000)


class CheckoutBody(BaseModel):
    items: list[dict]
    clubcard: bool = False
    coupon: bool = False


def require_admin(request: Request):
    if request.session.get("is_admin") is not True:
        raise HTTPException(status_code=401, detail="Najprv sa prihlás ako administrátor.")


def check_origin(request: Request):
    # Ochrana pred jednoduchými cross-site POST požiadavkami. API používaj cez tú istú doménu.
    origin = request.headers.get("origin")
    if origin:
        expected = str(request.base_url).rstrip("/")
        if origin.rstrip("/") != expected:
            raise HTTPException(status_code=403, detail="Požiadavka z inej domény bola odmietnutá.")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    return templates.TemplateResponse(request=request, name="admin.html", context={})


@app.get("/api/products")
def get_products():
    with db_connect() as conn:
        rows = conn.execute(
            "SELECT id, name, price, stock FROM products ORDER BY id"
        ).fetchall()
    return [{"id": r["id"], "name": r["name"], "price": float(r["price"]), "stock": r["stock"]} for r in rows]


@app.post("/api/admin/login")
def admin_login(body: LoginBody, request: Request):
    check_origin(request)
    # PIN sa porovnáva na serveri; nikdy ho neposielame do HTML/JavaScriptu.
    if not secrets.compare_digest(body.pin, ADMIN_PIN):
        raise HTTPException(status_code=401, detail="Nesprávny PIN.")
    request.session.clear()
    request.session["is_admin"] = True
    return {"success": True}


@app.post("/api/admin/logout")
def admin_logout(request: Request):
    check_origin(request)
    request.session.clear()
    return {"success": True}


@app.get("/api/admin/status")
def admin_status(request: Request):
    return {"is_admin": request.session.get("is_admin") is True}


@app.post("/api/admin/products/{product_id}/stock")
def add_stock(product_id: int, body: StockBody, request: Request):
    check_origin(request)
    require_admin(request)
    with db_connect() as conn:
        row = conn.execute(
            """UPDATE products SET stock = stock + %s
               WHERE id = %s RETURNING id, name, price, stock""",
            (body.amount, product_id),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Produkt sa nenašiel.")
    return {"id": row["id"], "name": row["name"], "price": float(row["price"]), "stock": row["stock"]}


@app.post("/api/checkout")
def checkout(body: CheckoutBody, request: Request):
    check_origin(request)
    if not body.items or len(body.items) > 50:
        raise HTTPException(status_code=400, detail="Košík je prázdny alebo príliš veľký.")

    # Normalizácia ID a množstva; klientom dodané ceny sa nikdy nepoužívajú.
    quantities = {}
    for item in body.items:
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail="Neplatná položka košíka.")
        try:
            product_id = int(item.get("id"))
            qty = int(item.get("quantity", 1))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Neplatné ID alebo množstvo.")
        if qty < 1 or qty > 20:
            raise HTTPException(status_code=400, detail="Množstvo musí byť od 1 do 20.")
        quantities[product_id] = quantities.get(product_id, 0) + qty
    if len(quantities) > 20:
        raise HTTPException(status_code=400, detail="Príliš veľa rôznych produktov.")

    with db_connect() as conn:
        products = []
        subtotal = Decimal("0.00")
        # Zámok riadkov a transakcia zabránia predaju väčšieho množstva, než je sklad.
        for product_id in sorted(quantities):
            row = conn.execute(
                "SELECT id, name, price, stock FROM products WHERE id = %s FOR UPDATE",
                (product_id,),
            ).fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="Košík obsahuje neznámy produkt.")
            qty = quantities[product_id]
            if row["stock"] < qty:
                raise HTTPException(status_code=409, detail=f"Nedostatok na sklade: {row['name']}.")
            subtotal += row["price"] * qty
            products.append((row, qty))

        total = subtotal
        if body.clubcard:
            total *= Decimal("0.90")
        if body.coupon:
            total *= Decimal("0.80")
        total = total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        order = conn.execute(
            "INSERT INTO orders (total) VALUES (%s) RETURNING id", (total,)
        ).fetchone()
        order_id = order["id"]
        for row, qty in products:
            conn.execute(
                "UPDATE products SET stock = stock - %s WHERE id = %s",
                (qty, row["id"]),
            )
            conn.execute(
                """INSERT INTO order_items
                   (order_id, product_id, product_name, unit_price, quantity)
                   VALUES (%s, %s, %s, %s, %s)""",
                (order_id, row["id"], row["name"], row["price"], qty),
            )
    return {"success": True, "order_id": order_id, "total": float(total)}


@app.get("/health")
def health():
    with db_connect() as conn:
        conn.execute("SELECT 1")
    return {"ok": True}


# Basic security headers for all responses.
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response
