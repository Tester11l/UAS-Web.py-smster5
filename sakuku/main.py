import base64, csv, hashlib, hmac, io, json, os, re, secrets
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import date, datetime, time, timedelta
from time import time as unix_time

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from qrcode.image.svg import SvgPathImage
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

from models import (AuditLog, BiayaAdmin, Base, JenisRekening, Kategori, Nasabah, Rekening,
                    LimitTransfer, PengajuanRekening, SessionLocal, Transaksi, User, engine, now, today)

SECRET_KEY = os.getenv("SECRET_KEY", "dev-ganti-di-produksi")
TOTP_LOGIN_CHALLENGE_SECONDS = 5 * 60
TOTP_CIPHER = Fernet(base64.urlsafe_b64encode(
    hashlib.sha256(f"{SECRET_KEY}:sakuku:totp".encode()).digest()))

BLN = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"]
TIPE = {  # tipe: (label, ikon, warna)
    "setor": ("Setoran tunai", "down", "lime"),
    "tarik": ("Tarik tunai", "up", "amber"),
    "transfer_keluar": ("Transfer keluar", "swap", "sky"),
    "transfer_masuk": ("Transfer masuk", "swap", "mint"),
    "biaya": ("Biaya admin", "percent", "rose"),
}


# ---------- setup ----------
def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()


def check_pw(pw: str, stored: str) -> bool:
    salt, h = stored.split("$", 1)
    return hmac.compare_digest(h, hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex())


def seed():
    with SessionLocal() as db:
        if not db.scalar(select(func.count(JenisRekening.id))):
            db.add_all([JenisRekening(nama="Tabungan", saldo_min=50000, keterangan="Rekening harian"),
                        JenisRekening(nama="Tabungan Pelajar", saldo_min=10000, keterangan="Untuk pelajar & mahasiswa"),
                        JenisRekening(nama="Giro", saldo_min=500000, keterangan="Untuk usaha")])
        if not db.scalar(select(func.count(Kategori.id))):
            db.add_all([Kategori(nama=n) for n in ["Gaji", "Belanja", "Makanan", "Tagihan", "Transportasi", "Hiburan", "Lainnya"]])
        if not db.scalar(select(func.count(BiayaAdmin.id))):
            db.add_all([BiayaAdmin(tipe="setor", nominal=0), BiayaAdmin(tipe="tarik", nominal=0),
                        BiayaAdmin(tipe="transfer", nominal=2500)])
        if not db.scalar(select(func.count(User.id)).where(User.role == "admin")):
            db.add(User(username=os.getenv("ADMIN_USER", "admin"), nama="Teller Utama", role="admin",
                        password=hash_pw(os.getenv("ADMIN_PASSWORD", "admin123"))))
        db.commit()


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    if engine.dialect.name == "sqlite":
        sqlite_columns = {
            "totp_enabled": "BOOLEAN NOT NULL DEFAULT 0",
            "totp_secret": "VARCHAR(256)",
            "totp_pending_secret": "VARCHAR(256)",
            "totp_pending_at": "DATETIME",
            "totp_recovery_codes": "VARCHAR(2000)",
        }
        with engine.begin() as conn:
            existing = {column["name"] for column in inspect(conn).get_columns("users")}
            for name, declaration in sqlite_columns.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {name} {declaration}"))
    seed()
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, max_age=60 * 60 * 8)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.filters["rp"] = lambda v: ("-" if (v or 0) < 0 else "") + "Rp " + f"{abs(int(v or 0)):,}".replace(",", ".")
templates.env.filters["tgl"] = lambda d: f"{d.day} {BLN[d.month - 1]} {d.year}" if d else "-"
templates.env.filters["wkt"] = lambda d: f"{d.day} {BLN[d.month - 1]} {d.year}, {d:%H:%M}" if d else "-"
templates.env.globals["TIPE"] = TIPE


# ---------- helpers ----------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class NeedLogin(Exception): pass
class Forbidden(Exception): pass


def flash(request, msg, kind="ok"):
    request.session["flash"] = [kind, msg]


@app.exception_handler(NeedLogin)
async def _need_login(request, exc):
    return RedirectResponse("/login", 303)


@app.exception_handler(Forbidden)
async def _forbidden(request, exc):
    flash(request, "Anda tidak punya akses ke halaman itu.", "err")
    return RedirectResponse("/dashboard", 303)


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("uid")
    user = db.get(User, uid) if uid else None
    if not user:
        raise NeedLogin()
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise Forbidden()
    return user


def page(request, tpl, user=None, **ctx):
    return templates.TemplateResponse(request, tpl, {"user": user, "admin": bool(user and user.role == "admin"),
                                                     "flash": request.session.pop("flash", None), **ctx})


def encrypt_totp_secret(secret: str) -> str:
    return TOTP_CIPHER.encrypt(secret.encode()).decode()


def decrypt_totp_secret(encrypted: str) -> str:
    return TOTP_CIPHER.decrypt(encrypted.encode()).decode()


def recovery_hash(code: str) -> str:
    normalized = code.replace("-", "").strip().upper()
    return hashlib.sha256(normalized.encode()).hexdigest()


def new_recovery_codes():
    codes = [secrets.token_hex(5).upper() for _ in range(8)]
    display = [f"{code[:5]}-{code[5:]}" for code in codes]
    hashed = [recovery_hash(code) for code in codes]
    return display, json.dumps(hashed)


def verify_totp_or_recovery(user: User, code: str, secret: str):
    normalized = re.sub(r"\s+", "", code or "").upper()
    if re.fullmatch(r"\d{6}", normalized) and pyotp.TOTP(secret).verify(normalized, valid_window=1):
        return True, False
    hashes = json.loads(user.totp_recovery_codes or "[]")
    if not isinstance(hashes, list) or not all(isinstance(value, str) for value in hashes):
        raise ValueError("Kode pemulihan akun tidak valid.")
    candidate = recovery_hash(normalized)
    for index, value in enumerate(hashes):
        if hmac.compare_digest(candidate, value):
            hashes.pop(index)
            user.totp_recovery_codes = json.dumps(hashes)
            return True, True
    return False, False


def pending_totp_secret(user: User):
    if not user.totp_pending_secret or not user.totp_pending_at:
        return None
    if now() - user.totp_pending_at > timedelta(minutes=10):
        user.totp_pending_secret = None
        user.totp_pending_at = None
        return None
    return decrypt_totp_secret(user.totp_pending_secret)


def pending_totp_login_user(request: Request, db: Session):
    uid = request.session.get("2fa_uid")
    started_at = request.session.get("2fa_started_at")
    user = db.get(User, uid) if uid else None
    valid_challenge = (isinstance(started_at, int) and
                       0 <= unix_time() - started_at <= TOTP_LOGIN_CHALLENGE_SECONDS)
    if not user or not user.totp_enabled or not user.totp_secret or not valid_challenge:
        request.session.clear()
        return None
    return user


def qr_data_uri(uri: str) -> str:
    image = qrcode.make(uri, image_factory=SvgPathImage, box_size=5, border=2)
    output = io.BytesIO()
    image.save(output)
    return "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode()


def go(url): return RedirectResponse(url, 303)


def rupiah(v) -> int:
    return int(re.sub(r"\D", "", str(v or "")) or 0)


def tgl(s):
    try:
        return date.fromisoformat(s) if s else None
    except ValueError:
        return None


def log(db, user, aksi, detail=""):
    db.add(AuditLog(user_id=user.id if user else None, aksi=aksi, detail=detail[:300]))


def boleh(user, rek) -> bool:
    return user.role == "admin" or rek.nasabah_id == user.nasabah_id


def no_baru(db) -> str:
    while True:
        n = "88" + "".join(secrets.choice("0123456789") for _ in range(8))
        if not db.scalar(select(Rekening.id).where(Rekening.no_rekening == n)):
            return n


def biaya(db, tipe) -> int:
    b = db.scalar(select(BiayaAdmin).where(BiayaAdmin.tipe == tipe))
    return b.nominal if b else 0


def kunci(db, *nomor):
    """Ambil rekening + kunci baris (urut id supaya tidak deadlock). Return dict no -> Rekening."""
    rows = db.scalars(select(Rekening).where(Rekening.no_rekening.in_([n.strip() for n in nomor]))
                      .order_by(Rekening.id).with_for_update()).all()
    return {r.no_rekening: r for r in rows}


def catat(db, rek, jumlah, tipe, user, kategori_id=None, lawan=None, ket=""):
    """Satu-satunya tempat saldo berubah: update saldo + tulis baris buku besar."""
    rek.saldo += jumlah
    db.add(Transaksi(rekening=rek, tipe=tipe, jumlah=jumlah, saldo_akhir=rek.saldo, kategori_id=kategori_id,
                     lawan=lawan, keterangan=ket.strip()[:200], user_id=user.id))


def sisa_ok(rek, total):
    return rek.saldo - total >= rek.jenis.saldo_min


def enam_bulan():
    t, out = today(), []
    for i in range(5, -1, -1):
        y, m = t.year, t.month - i
        while m <= 0:
            m, y = m + 12, y - 1
        out.append((y, m))
    return out


def q_trx(db, ids=None, dari=None, sampai=None, tipe="", no=""):
    stmt = select(Transaksi).order_by(Transaksi.waktu.desc(), Transaksi.id.desc())
    if ids is not None:
        stmt = stmt.where(Transaksi.rekening_id.in_(ids))
    if dari:
        stmt = stmt.where(Transaksi.waktu >= datetime.combine(dari, time.min))
    if sampai:
        stmt = stmt.where(Transaksi.waktu < datetime.combine(sampai + timedelta(days=1), time.min))
    if tipe:
        stmt = stmt.where(Transaksi.tipe == tipe)
    if no:
        stmt = stmt.join(Rekening, Transaksi.rekening_id == Rekening.id).where(Rekening.no_rekening.contains(no))
    return db.scalars(stmt).all()


def ids_milik(db, user):
    if user.role == "admin":
        return None
    return list(db.scalars(select(Rekening.id).where(Rekening.nasabah_id == user.nasabah_id)))


def halaman(page: int, per_page: int, total: int):
    page = max(1, int(page or 1))
    per_page = max(10, min(100, int(per_page or 20)))
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    return page, per_page, pages


# ---------- AUTH ----------
@app.get("/")
def root(request: Request):
    return go("/dashboard" if request.session.get("uid") else "/login")


@app.get("/login")
def login_form(request: Request):
    return page(request, "login.html")


@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    f = await request.form()
    u = db.scalar(select(User).where(User.username == f.get("username", "").strip()))
    if not u or not check_pw(f.get("password", ""), u.password):
        flash(request, "Username atau password salah.", "err")
        return go("/login")
    request.session.clear()
    if u.totp_enabled:
        request.session["2fa_uid"] = u.id
        request.session["2fa_started_at"] = int(unix_time())
        return go("/login/2fa")
    request.session["uid"] = u.id
    return go("/dashboard")


@app.get("/login/2fa")
def login_2fa_form(request: Request, db: Session = Depends(get_db)):
    user = pending_totp_login_user(request, db)
    if not user:
        flash(request, "Sesi verifikasi berakhir atau tidak valid. Silakan masuk kembali.", "err")
        return go("/login")
    return page(request, "login_2fa.html", username=user.username)


@app.post("/login/2fa")
async def login_2fa(request: Request, db: Session = Depends(get_db)):
    user = pending_totp_login_user(request, db)
    if not user:
        flash(request, "Sesi verifikasi berakhir atau tidak valid. Silakan masuk kembali.", "err")
        return go("/login")
    form = await request.form()
    try:
        valid, used_recovery = verify_totp_or_recovery(
            user, form.get("code", ""), decrypt_totp_secret(user.totp_secret))
    except (InvalidToken, UnicodeDecodeError, ValueError):
        request.session.clear()
        flash(request, "Pengaturan 2FA tidak dapat dibaca. Hubungi petugas.", "err")
        return go("/login")
    if not valid:
        flash(request, "Kode verifikasi tidak sesuai.", "err")
        return go("/login/2fa")
    if used_recovery:
        db.commit()
    request.session.clear()
    request.session["uid"] = user.id
    return go("/dashboard")


@app.get("/register")
def register_form(request: Request):
    return page(request, "register.html")


@app.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    f = await request.form()
    v = {k: f.get(k, "").strip() for k in ("nik", "nama", "alamat", "no_hp", "username")}
    pw = f.get("password", "")
    if not (v["nik"] and v["nama"] and v["username"]) or len(pw) < 6:
        flash(request, "NIK, nama, username wajib diisi. Password minimal 6 karakter.", "err")
        return go("/register")
    n = Nasabah(nik=v["nik"], nama=v["nama"], alamat=v["alamat"], no_hp=v["no_hp"])
    db.add(n)
    try:
        db.flush()
        db.add(User(username=v["username"], nama=v["nama"], password=hash_pw(pw), role="nasabah", nasabah_id=n.id))
        db.commit()
    except IntegrityError:
        db.rollback()
        flash(request, "NIK atau username sudah terdaftar.", "err")
        return go("/register")
    flash(request, "Akun dibuat. Silakan masuk.")
    return go("/login")


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return go("/login")


# ---------- DASHBOARD ----------
@app.get("/dashboard")
def dashboard(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    admin = user.role == "admin"
    ids = ids_milik(db, user)
    reks = [] if admin else db.scalars(select(Rekening).where(Rekening.nasabah_id == user.nasabah_id)
                                        .order_by(Rekening.id)).all()
    recent = q_trx(db, ids)[:6]
    # grafik 6 bulan: nasabah = masuk vs keluar, petugas = setoran vs penarikan tunai
    bulan = enam_bulan()
    mulai = datetime(bulan[0][0], bulan[0][1], 1)
    data = {b: [0, 0] for b in bulan}
    for t in db.scalars(select(Transaksi).where(Transaksi.waktu >= mulai).where(
            True if ids is None else Transaksi.rekening_id.in_(ids))):
        k = (t.waktu.year, t.waktu.month)
        if admin:
            if t.tipe == "setor": data[k][0] += t.jumlah
            elif t.tipe == "tarik": data[k][1] += -t.jumlah
        else:
            data[k][0 if t.jumlah > 0 else 1] += abs(t.jumlah)
    mx = max([1] + [x for v in data.values() for x in v])
    chart = [dict(label=BLN[m - 1], masuk=v[0], keluar=v[1], hm=round(v[0] * 100 / mx), hk=round(v[1] * 100 / mx))
             for (y, m), v in data.items()]
    stat = {}
    if admin:
        stat = dict(
            nasabah=db.scalar(select(func.count(Nasabah.id))),
            rekening=db.scalar(select(func.count(Rekening.id)).where(Rekening.status == "aktif")),
            dana=db.scalar(select(func.coalesce(func.sum(Rekening.saldo), 0)).where(Rekening.status != "tutup")),
            hari_ini=db.scalar(select(func.count(Transaksi.id)).where(
                Transaksi.waktu >= datetime.combine(today(), time.min), Transaksi.tipe != "transfer_masuk")),
            fee=-db.scalar(select(func.coalesce(func.sum(Transaksi.jumlah), 0)).where(Transaksi.tipe == "biaya")))
    total = sum(r.saldo for r in reks if r.status != "tutup")
    return page(request, "dashboard.html", user, tab="dashboard", reks=reks, recent=recent, chart=chart,
                stat=stat, total=total)


# ---------- FILE MASTER (CRUD generik) ----------
MASTER = {
    "nasabah": dict(model=Nasabah, judul="Data nasabah", ikon="users", unik="NIK", tone="sky",
                    fields=[("nik", "NIK", "text"), ("nama", "Nama", "text"), ("alamat", "Alamat", "text"),
                            ("no_hp", "No. HP", "text")],
                    used=lambda: [Rekening.nasabah_id, User.nasabah_id]),
    "jenis": dict(model=JenisRekening, judul="Jenis rekening", ikon="layers", unik="Nama jenis", tone="lilac",
                  fields=[("nama", "Nama", "text"), ("saldo_min", "Saldo minimum (Rp)", "number"),
                          ("keterangan", "Keterangan", "text")], used=lambda: [Rekening.jenis_id]),
    "kategori": dict(model=Kategori, judul="Kategori transaksi", ikon="tag", unik="Nama kategori", tone="amber",
                     fields=[("nama", "Nama", "text")], used=lambda: [Transaksi.kategori_id]),
    "biaya": dict(model=BiayaAdmin, judul="Biaya admin", ikon="percent", unik="Tipe biaya", tone="rose",
                  fields=[("tipe", "Tipe", "select:setor,tarik,transfer"), ("nominal", "Nominal (Rp)", "number")],
                  used=lambda: []),
    "petugas": dict(model=User, judul="Petugas / teller", ikon="shield", unik="Username", tone="mint",
                    fields=[("username", "Username", "text"), ("nama", "Nama", "text"),
                            ("password", "Password", "password")],
                    where=lambda M: M.role == "admin", defaults={"role": "admin"},
                    used=lambda: [Transaksi.user_id, AuditLog.user_id]),
}


def cfg(name):
    if name not in MASTER:
        raise Forbidden()
    return MASTER[name]


@app.get("/master/{name}")
def master_list(name: str, request: Request, q: str = "", edit: int = 0,
                pagination_page: int = 1, user=Depends(require_admin), db: Session = Depends(get_db)):
    c = cfg(name)
    M = c["model"]
    stmt = select(M).order_by(M.id.desc())
    if c.get("where"):
        stmt = stmt.where(c["where"](M))
    if q:
        stmt = stmt.where(getattr(M, c["fields"][0][0]).ilike(f"%{q}%") | getattr(M, c["fields"][1][0]).ilike(f"%{q}%")
                          if len(c["fields"]) > 1 and c["fields"][1][2] == "text"
                          else getattr(M, c["fields"][0][0]).ilike(f"%{q}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    page_no, per_page, pages = halaman(pagination_page, 20, total)
    item = db.get(M, edit) if edit else None
    rows = db.scalars(stmt.limit(per_page).offset((page_no - 1) * per_page)).all()
    return page(request, "master.html", user, name=name, c=c, rows=rows, q=q, item=item, tab=name,
                edit=edit, pagination={"page": page_no, "pages": pages, "per": per_page, "total": total})


@app.post("/master/{name}/simpan")
async def master_save(name: str, request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    c = cfg(name)
    f = await request.form()
    pk = f.get("id")
    data, wajib = {}, [k for k, _, t in c["fields"][:2] if t != "number" and t != "password"]
    for key, _, typ in c["fields"]:
        v = f.get(key, "") if typ == "password" else f.get(key, "").strip()
        if typ == "number":
            data[key] = rupiah(v)
        elif typ == "password":
            if v:
                data[key] = hash_pw(v)
            elif not pk:
                flash(request, "Password wajib diisi.", "err")
                return go(f"/master/{name}")
        else:
            data[key] = v
    if any(not data[k] for k in wajib):
        flash(request, "Kolom wajib belum diisi.", "err")
        return go(f"/master/{name}")
    obj = db.get(c["model"], int(pk)) if pk else c["model"](**c.get("defaults", {}))
    for k, v in data.items():
        setattr(obj, k, v)
    db.add(obj)
    try:
        log(db, user, "master_ubah" if pk else "master_tambah", f"{name}: {data.get(c['fields'][0][0])}")
        db.commit()
        flash(request, "Data diperbarui." if pk else "Data ditambahkan.")
    except IntegrityError:
        db.rollback()
        flash(request, f"{c['unik']} sudah terdaftar.", "err")
    return go(f"/master/{name}")


@app.post("/master/{name}/{id}/hapus")
def master_delete(name: str, id: int, request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    c = cfg(name)
    obj = db.get(c["model"], id)
    if not obj or (name == "petugas" and (obj.id == user.id or obj.role != "admin")):
        flash(request, "Data tidak bisa dihapus.", "err")
    elif any(db.scalar(select(func.count()).select_from(col.class_).where(col == id)) for col in c["used"]()):
        flash(request, "Tidak bisa dihapus: data sudah dipakai di tabel lain.", "err")
    else:
        db.delete(obj)
        log(db, user, "master_hapus", f"{name} #{id}")
        db.commit()
        flash(request, "Data dihapus.")
    return go(f"/master/{name}")


# ---------- REKENING ----------
@app.get("/rekening")
def rekening_list(request: Request, q: str = "", pagination_page: int = 1, user=Depends(require_user),
                  db: Session = Depends(get_db)):
    stmt = select(Rekening).join(Nasabah).order_by(Rekening.id.desc())
    if user.role != "admin":
        stmt = stmt.where(Rekening.nasabah_id == user.nasabah_id)
    if q:
        stmt = stmt.where(Rekening.no_rekening.contains(q) | Nasabah.nama.ilike(f"%{q}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    page_no, per_page, pages = halaman(pagination_page, 20, total)
    rows = db.scalars(stmt.limit(per_page).offset((page_no - 1) * per_page)).all()
    pengajuan = []
    if user.role == "admin":
        pengajuan = db.scalars(select(PengajuanRekening).where(
            PengajuanRekening.status == "menunggu").order_by(PengajuanRekening.dibuat.desc())).all()
    else:
        pengajuan = db.scalars(select(PengajuanRekening).where(
            PengajuanRekening.nasabah_id == user.nasabah_id).order_by(PengajuanRekening.dibuat.desc())).all()
    return page(request, "rekening.html", user, tab="rekening", rows=rows, q=q,
                nasabah=db.scalars(select(Nasabah).order_by(Nasabah.nama)).all() if user.role == "admin" else [],
                jenis=db.scalars(select(JenisRekening).order_by(JenisRekening.id)).all(),
                pengajuan=pengajuan, pagination={"page": page_no, "pages": pages, "per": per_page,
                                                  "total": total})


@app.post("/rekening/buka")
async def rekening_buka(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    f = await request.form()
    try:
        nid = int(f["nasabah_id"]) if user.role == "admin" else user.nasabah_id
        jenis = db.get(JenisRekening, int(f["jenis_id"]))
    except (KeyError, ValueError, TypeError):
        nid = jenis = None
    n = db.get(Nasabah, nid) if nid else None
    if not n or not jenis:
        flash(request, "Pilih nasabah dan jenis rekening.", "err")
        return go("/rekening")
    r = Rekening(no_rekening=no_baru(db), nasabah_id=n.id, jenis_id=jenis.id)
    db.add(r)
    log(db, user, "buka_rekening", f"{r.no_rekening} a/n {n.nama} ({jenis.nama})")
    db.commit()
    flash(request, f"Rekening {jenis.nama} dibuka: {r.no_rekening}.")
    return go(f"/rekening/{r.id}")


@app.get("/rekening/{id}")
def rekening_detail(id: int, request: Request, dari: str = "", sampai: str = "",
                    user=Depends(require_user), db: Session = Depends(get_db)):
    r = db.get(Rekening, id)
    if not r or not boleh(user, r):
        raise Forbidden()
    rows = q_trx(db, [r.id], tgl(dari), tgl(sampai))
    return page(request, "rekening_detail.html", user, tab="rekening", r=r, rows=rows, dari=dari, sampai=sampai,
                masuk=sum(t.jumlah for t in rows if t.jumlah > 0), keluar=-sum(t.jumlah for t in rows if t.jumlah < 0))


@app.get("/rekening/{id}/csv")
def rekening_csv(id: int, dari: str = "", sampai: str = "", user=Depends(require_user), db: Session = Depends(get_db)):
    r = db.get(Rekening, id)
    if not r or not boleh(user, r):
        raise Forbidden()
    return csv_response(q_trx(db, [r.id], tgl(dari), tgl(sampai)), f"mutasi_{r.no_rekening}.csv")


@app.post("/rekening/{id}/status")
async def rekening_status(id: int, request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    f = await request.form()
    aksi = f.get("aksi")
    r = db.get(Rekening, id)
    if not r or aksi not in ("aktif", "beku", "tutup"):
        raise Forbidden()
    if aksi == "tutup" and r.saldo != 0:
        flash(request, "Rekening hanya bisa ditutup jika saldo Rp 0.", "err")
    else:
        r.status = aksi
        log(db, user, f"rekening_{aksi}", r.no_rekening)
        db.commit()
        flash(request, f"Status rekening menjadi {aksi}.")
    return go(f"/rekening/{id}")


@app.post("/rekening/pengajuan")
async def rekening_pengajuan(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    if user.role != "nasabah":
        raise Forbidden()
    f = await request.form()
    try:
        jenis = db.get(JenisRekening, int(f["jenis_id"]))
    except (KeyError, ValueError, TypeError):
        jenis = None
    if not jenis:
        flash(request, "Jenis rekening belum dipilih.", "err")
        return go("/rekening")
    ada = db.scalar(select(PengajuanRekening.id).where(
        PengajuanRekening.nasabah_id == user.nasabah_id,
        PengajuanRekening.jenis_id == jenis.id,
        PengajuanRekening.status == "menunggu"))
    if ada:
        flash(request, "Pengajuan untuk jenis rekening ini masih menunggu persetujuan.", "err")
        return go("/rekening")
    db.add(PengajuanRekening(nasabah_id=user.nasabah_id, jenis_id=jenis.id,
                             catatan=f.get("catatan", "").strip()[:300]))
    log(db, user, "ajukan_rekening", f"{jenis.nama}")
    db.commit()
    flash(request, "Pengajuan rekening dikirim. Menunggu persetujuan petugas.")
    return go("/rekening")


@app.post("/rekening/pengajuan/{id}/proses")
async def rekening_pengajuan_proses(id: int, request: Request, user=Depends(require_admin),
                                    db: Session = Depends(get_db)):
    f = await request.form()
    aksi = f.get("aksi")
    pengajuan = db.get(PengajuanRekening, id)
    if not pengajuan or aksi not in ("disetujui", "ditolak"):
        raise Forbidden()
    if pengajuan.status != "menunggu":
        flash(request, "Pengajuan sudah diproses.", "err")
        return go("/rekening")
    if aksi == "disetujui":
        r = Rekening(no_rekening=no_baru(db), nasabah_id=pengajuan.nasabah_id,
                     jenis_id=pengajuan.jenis_id)
        db.add(r)
    pengajuan.status = aksi
    pengajuan.catatan = f.get("catatan", "").strip()[:300] or pengajuan.catatan
    pengajuan.diproses = now()
    pengajuan.petugas_id = user.id
    log(db, user, f"pengajuan_{aksi}", f"pengajuan #{id}")
    db.commit()
    flash(request, "Pengajuan rekening disetujui." if aksi == "disetujui" else "Pengajuan rekening ditolak.")
    return go("/rekening")


# ---------- TRANSAKSI ----------
@app.get("/transaksi")
def transaksi_page(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    ids = ids_milik(db, user)
    punya = [] if user.role == "admin" else db.scalars(select(Rekening).where(
        Rekening.nasabah_id == user.nasabah_id, Rekening.status == "aktif")).all()
    return page(request, "transaksi.html", user, tab="transaksi", punya=punya, recent=q_trx(db, ids)[:10],
                kategori=db.scalars(select(Kategori).order_by(Kategori.nama)).all(),
                fee={t: biaya(db, t) for t in ("setor", "tarik", "transfer")})


def gagal(request, msg):
    flash(request, msg, "err")
    return go("/transaksi")


@app.post("/transaksi/setor")
async def setor(request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    f = await request.form()
    jumlah, no = rupiah(f.get("jumlah")), f.get("no_rekening", "").strip()
    r = kunci(db, no).get(no)
    if not r or r.status != "aktif":
        return gagal(request, "Rekening tidak ditemukan atau tidak aktif.")
    if jumlah <= 0:
        return gagal(request, "Jumlah setoran harus lebih dari 0.")
    fee = biaya(db, "setor")
    if fee > jumlah:
        return gagal(request, "Setoran lebih kecil dari biaya admin.")
    kat = int(f["kategori_id"]) if f.get("kategori_id") else None
    catat(db, r, jumlah, "setor", user, kat, ket=f.get("keterangan", ""))
    if fee:
        catat(db, r, -fee, "biaya", user, ket="Biaya setor")
    log(db, user, "setor", f"{no} +{jumlah}")
    db.commit()
    flash(request, f"Setoran {jumlah:,} ke {r.nasabah.nama} berhasil. Saldo: {r.saldo:,}".replace(",", "."))
    return go("/transaksi")


@app.post("/transaksi/tarik")
async def tarik(request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    f = await request.form()
    jumlah, no = rupiah(f.get("jumlah")), f.get("no_rekening", "").strip()
    r = kunci(db, no).get(no)
    if not r or r.status != "aktif":
        return gagal(request, "Rekening tidak ditemukan atau tidak aktif.")
    fee = biaya(db, "tarik")
    if jumlah <= 0:
        return gagal(request, "Jumlah penarikan harus lebih dari 0.")
    if not sisa_ok(r, jumlah + fee):
        return gagal(request, f"Saldo tidak cukup. Saldo minimum {r.jenis.saldo_min:,} harus tersisa.".replace(",", "."))
    kat = int(f["kategori_id"]) if f.get("kategori_id") else None
    catat(db, r, -jumlah, "tarik", user, kat, ket=f.get("keterangan", ""))
    if fee:
        catat(db, r, -fee, "biaya", user, ket="Biaya tarik tunai")
    log(db, user, "tarik", f"{no} -{jumlah}")
    db.commit()
    flash(request, f"Penarikan {jumlah:,} dari {r.nasabah.nama} berhasil. Saldo: {r.saldo:,}".replace(",", "."))
    return go("/transaksi")


@app.post("/transaksi/transfer")
async def transfer(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    f = await request.form()
    dari_no, ke_no, jumlah = f.get("dari", "").strip(), f.get("ke", "").strip(), rupiah(f.get("jumlah"))
    if not dari_no or not ke_no:
        return gagal(request, "Isi rekening asal dan tujuan.")
    if dari_no == ke_no:
        return gagal(request, "Rekening asal dan tujuan tidak boleh sama.")
    m = kunci(db, dari_no, ke_no)
    asal, tujuan = m.get(dari_no), m.get(ke_no)
    if not asal or not boleh(user, asal):
        return gagal(request, "Rekening asal tidak valid.")
    if not tujuan:
        return gagal(request, "Rekening tujuan tidak ditemukan.")
    if asal.status != "aktif" or tujuan.status != "aktif":
        return gagal(request, "Rekening asal/tujuan sedang beku atau ditutup.")
    if jumlah <= 0:
        return gagal(request, "Jumlah transfer harus lebih dari 0.")
    fee = biaya(db, "transfer")
    limit = db.scalar(select(LimitTransfer).where(LimitTransfer.nasabah_id == asal.nasabah_id))
    limit_per = limit.per_transaksi if limit else 10_000_000
    limit_harian = limit.harian if limit else 50_000_000
    if jumlah > limit_per:
        return gagal(request, f"Jumlah transfer melebihi limit per transaksi {limit_per:,}.")
    mulai_hari = datetime.combine(today(), time.min)
    sudah = db.scalar(select(func.coalesce(func.sum(Transaksi.jumlah), 0)).where(
        Transaksi.rekening_id == asal.id,
        Transaksi.tipe == "transfer_keluar",
        Transaksi.waktu >= mulai_hari)) or 0
    sudah = abs(sudah)
    if sudah + jumlah > limit_harian:
        return gagal(request, f"Limit transfer harian tersisa {max(limit_harian - sudah, 0):,}.")
    if not sisa_ok(asal, jumlah + fee):
        return gagal(request, f"Saldo tidak cukup. Saldo minimum {asal.jenis.saldo_min:,} harus tersisa.".replace(",", "."))
    kat = int(f["kategori_id"]) if f.get("kategori_id") else None
    ket = f.get("keterangan", "")
    catat(db, asal, -jumlah, "transfer_keluar", user, kat, lawan=tujuan, ket=ket)
    if fee:
        catat(db, asal, -fee, "biaya", user, ket="Biaya transfer")
    catat(db, tujuan, jumlah, "transfer_masuk", user, kat, lawan=asal, ket=ket)
    log(db, user, "transfer", f"{dari_no} -> {ke_no} {jumlah}")
    db.commit()  # semua atau tidak sama sekali
    flash(request, f"Transfer {jumlah:,} ke {tujuan.nasabah.nama} ({ke_no}) berhasil.".replace(",", "."))
    return go("/transaksi")


# ---------- LAPORAN ----------
def csv_response(rows, nama):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Waktu", "No Rekening", "Nasabah", "Tipe", "Lawan", "Keterangan", "Jumlah", "Saldo Akhir"])
    for t in rows:
        w.writerow([t.waktu, t.rekening.no_rekening, t.rekening.nasabah.nama, TIPE[t.tipe][0],
                    t.lawan.no_rekening if t.lawan else "", t.keterangan, t.jumlah, t.saldo_akhir])
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={nama}"})


@app.get("/laporan")
def laporan(request: Request, r: str = "mutasi", dari: str = "", sampai: str = "", tipe: str = "", no: str = "",
            user=Depends(require_user), db: Session = Depends(get_db)):
    admin = user.role == "admin"
    if r not in ("mutasi", "kategori") and not admin or r not in ("mutasi", "saldo", "harian", "biaya", "kategori"):
        r = "mutasi"
    ids, d1, d2 = ids_milik(db, user), tgl(dari), tgl(sampai)
    ctx = dict(r=r, dari=dari, sampai=sampai, tipe=tipe, no=no, tab="laporan")
    if r == "mutasi":
        rows = q_trx(db, ids, d1, d2, tipe, no if admin else "")
        ctx.update(rows=rows, masuk=sum(t.jumlah for t in rows if t.jumlah > 0),
                   keluar=-sum(t.jumlah for t in rows if t.jumlah < 0))
    elif r == "saldo":
        reks = db.scalars(select(Rekening).join(Nasabah).order_by(Nasabah.nama, Rekening.id)).all()
        pj = defaultdict(lambda: [0, 0])
        for x in reks:
            if x.status != "tutup":
                pj[x.jenis.nama][0] += 1
                pj[x.jenis.nama][1] += x.saldo
        ctx.update(reks=reks, per_jenis=sorted(pj.items()), total=sum(v[1] for v in pj.values()))
    elif r == "harian":
        g = defaultdict(lambda: dict(n=0, setor=0, tarik=0, transfer=0, biaya=0))
        for t in q_trx(db, None, d1, d2):
            x = g[t.waktu.date()]
            if t.tipe != "transfer_masuk":
                x["n"] += 1
            if t.tipe in ("setor", "tarik", "biaya"):
                x[t.tipe] += abs(t.jumlah)
            elif t.tipe == "transfer_keluar":
                x["transfer"] += abs(t.jumlah)
        ctx.update(harian=sorted(g.items(), reverse=True))
    elif r == "biaya":
        rows = q_trx(db, None, d1, d2, "biaya")
        ctx.update(rows=rows, total=-sum(t.jumlah for t in rows))
    else:  # kategori: pengeluaran per kategori
        g = defaultdict(int)
        for t in q_trx(db, ids, d1, d2):
            if t.jumlah < 0 and t.tipe in ("tarik", "transfer_keluar"):
                g[t.kategori.nama if t.kategori else "Tanpa kategori"] += -t.jumlah
        tot = sum(g.values()) or 1
        ctx.update(kat=[(k, v, round(v * 100 / tot)) for k, v in sorted(g.items(), key=lambda x: -x[1])], total=sum(g.values()))
    return page(request, "laporan.html", user, **ctx)


@app.get("/laporan/csv")
def laporan_csv(dari: str = "", sampai: str = "", tipe: str = "", no: str = "",
                user=Depends(require_user), db: Session = Depends(get_db)):
    return csv_response(q_trx(db, ids_milik(db, user), tgl(dari), tgl(sampai), tipe, no if user.role == "admin" else ""),
                        "laporan_mutasi.csv")


@app.get("/transaksi/{id}/pdf")
def transaksi_pdf(id: int, request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    t = db.get(Transaksi, id)
    if not t or not boleh(user, t.rekening):
        raise Forbidden()
    out = io.BytesIO()
    p = canvas.Canvas(out, pagesize=A4)
    p.setTitle(f"Bukti transaksi {id}")
    p.setFillColorRGB(0.07, 0.16, 0.29)
    p.rect(0, 277 * mm, 210 * mm, 20 * mm, fill=1, stroke=0)
    p.setFillColorRGB(1, 1, 1)
    p.setFont("Helvetica-Bold", 18)
    p.drawString(20 * mm, 287 * mm, "SAKUKU")
    p.setFont("Helvetica", 10)
    p.drawRightString(190 * mm, 287 * mm, "Bukti Transaksi")
    p.setFillColorRGB(0.12, 0.15, 0.18)
    y = 260 * mm
    p.setFont("Helvetica-Bold", 13)
    p.drawString(20 * mm, y, TIPE[t.tipe][0])
    y -= 12 * mm
    rows = [
        ("Nomor referensi", f"SK-{t.id:08d}"),
        ("Waktu", f"{t.waktu:%d %B %Y, %H:%M}"),
        ("No. rekening", t.rekening.no_rekening),
        ("Nasabah", t.rekening.nasabah.nama),
        ("Keterangan", t.keterangan or "-"),
        ("Jumlah", f"Rp {abs(t.jumlah):,.0f}".replace(",", ".")),
        ("Saldo akhir", f"Rp {t.saldo_akhir:,.0f}".replace(",", ".")),
    ]
    p.setFont("Helvetica", 11)
    for label, value in rows:
        p.setFillColorRGB(0.45, 0.50, 0.55)
        p.drawString(20 * mm, y, label)
        p.setFillColorRGB(0.12, 0.15, 0.18)
        p.drawRightString(190 * mm, y, str(value))
        y -= 10 * mm
    p.setStrokeColorRGB(0.82, 0.86, 0.90)
    p.line(20 * mm, 145 * mm, 190 * mm, 145 * mm)
    p.setFillColorRGB(0.45, 0.50, 0.55)
    p.setFont("Helvetica", 9)
    p.drawString(20 * mm, 35 * mm, "Dokumen ini dibuat oleh sistem Sakuku.")
    p.drawString(20 * mm, 30 * mm, "Harap simpan sebagai bukti transaksi.")
    p.showPage()
    p.save()
    out.seek(0)
    return Response(out.read(), media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=bukti_SK-{t.id:08d}.pdf"})


@app.get("/profil")
def profil(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    nasabah = db.get(Nasabah, user.nasabah_id) if user.nasabah_id else None
    limit = db.scalar(select(LimitTransfer).where(
        LimitTransfer.nasabah_id == user.nasabah_id)) if user.nasabah_id else None
    password_protected = bool(re.fullmatch(r"[0-9a-f]{16}\$[0-9a-f]{64}", user.password or ""))
    security = {
        "password_protected": password_protected,
        "phone_registered": bool(nasabah and nasabah.no_hp.strip()),
        "totp_enabled": user.totp_enabled,
        "status": "2FA aktif" if user.totp_enabled else (
            "Belum sepenuhnya aman" if password_protected else "Perlu tindakan"),
        "status_class": "good" if user.totp_enabled else (
            "warning" if password_protected else "danger"),
    }
    return page(request, "profil.html", user, tab="profil", nasabah=nasabah, limit=limit,
                security=security)


@app.post("/profil/2fa/setup")
def totp_setup(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    if user.totp_enabled:
        flash(request, "Verifikasi dua langkah sudah aktif.")
        return go("/profil")
    secret = pyotp.random_base32()
    user.totp_pending_secret = encrypt_totp_secret(secret)
    user.totp_pending_at = now()
    log(db, user, "2fa_mulai", "Pengaturan verifikasi dua langkah dimulai")
    db.commit()
    return go("/profil/2fa/setup")


@app.get("/profil/2fa/setup")
def totp_setup_page(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    if user.totp_enabled:
        return go("/profil")
    try:
        secret = pending_totp_secret(user)
    except (InvalidToken, UnicodeDecodeError):
        user.totp_pending_secret = None
        user.totp_pending_at = None
        db.commit()
        flash(request, "Pengaturan 2FA tidak dapat dibaca. Silakan mulai kembali.", "err")
        return go("/profil")
    if not secret:
        db.commit()
        flash(request, "Sesi pengaturan 2FA berakhir. Silakan mulai kembali.", "err")
        return go("/profil")
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="Sakuku")
    response = page(request, "2fa_setup.html", user, tab="profil", qr=qr_data_uri(uri), secret=secret)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/profil/2fa/confirm")
async def totp_confirm(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    if user.totp_enabled:
        flash(request, "Verifikasi dua langkah sudah aktif.")
        return go("/profil")
    try:
        secret = pending_totp_secret(user)
    except (InvalidToken, UnicodeDecodeError):
        user.totp_pending_secret = None
        user.totp_pending_at = None
        db.commit()
        flash(request, "Pengaturan 2FA tidak dapat dibaca. Silakan mulai kembali.", "err")
        return go("/profil")
    if not secret:
        db.commit()
        flash(request, "Sesi pengaturan 2FA berakhir. Silakan mulai kembali.", "err")
        return go("/profil")
    form = await request.form()
    code = re.sub(r"\s+", "", form.get("code", ""))
    if not re.fullmatch(r"\d{6}", code) or not pyotp.TOTP(secret).verify(code, valid_window=1):
        flash(request, "Kode authenticator tidak sesuai. Periksa waktu perangkat lalu coba lagi.", "err")
        return go("/profil/2fa/setup")
    recovery_codes, recovery_hashes = new_recovery_codes()
    user.totp_secret = user.totp_pending_secret
    user.totp_pending_secret = None
    user.totp_pending_at = None
    user.totp_recovery_codes = recovery_hashes
    user.totp_enabled = True
    log(db, user, "2fa_aktif", "Verifikasi dua langkah diaktifkan")
    db.commit()
    response = page(request, "2fa_recovery.html", user, tab="profil",
                    recovery_codes=recovery_codes)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/profil/2fa/cancel")
def totp_cancel(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    if not user.totp_enabled and user.totp_pending_secret:
        user.totp_pending_secret = None
        user.totp_pending_at = None
        log(db, user, "2fa_batal", "Pengaturan verifikasi dua langkah dibatalkan")
        db.commit()
    return go("/profil")


@app.post("/profil/2fa/disable")
async def totp_disable(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    if not user.totp_enabled or not user.totp_secret:
        flash(request, "Verifikasi dua langkah belum aktif.", "err")
        return go("/profil")
    form = await request.form()
    if not check_pw(form.get("password", ""), user.password):
        flash(request, "Password akun tidak sesuai.", "err")
        return go("/profil")
    try:
        valid, _ = verify_totp_or_recovery(
            user, form.get("code", ""), decrypt_totp_secret(user.totp_secret))
    except (InvalidToken, UnicodeDecodeError, ValueError):
        flash(request, "Pengaturan 2FA tidak dapat dibaca. Hubungi petugas.", "err")
        return go("/profil")
    if not valid:
        flash(request, "Kode authenticator atau recovery code tidak sesuai.", "err")
        return go("/profil")
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_pending_secret = None
    user.totp_pending_at = None
    user.totp_recovery_codes = None
    log(db, user, "2fa_nonaktif", "Verifikasi dua langkah dinonaktifkan")
    db.commit()
    flash(request, "Verifikasi dua langkah dinonaktifkan.")
    return go("/profil")


@app.post("/profil")
async def profil_simpan(request: Request, user=Depends(require_user), db: Session = Depends(get_db)):
    f = await request.form()
    lama = f.get("password_lama", "")
    baru = f.get("password_baru", "")
    konfirmasi = f.get("password_konfirmasi", "")
    if lama or baru or konfirmasi:
        if not check_pw(lama, user.password):
            flash(request, "Password lama tidak sesuai.", "err")
            return go("/profil")
        if len(baru) < 6:
            flash(request, "Password baru minimal 6 karakter.", "err")
            return go("/profil")
        if baru != konfirmasi:
            flash(request, "Konfirmasi password baru tidak sama.", "err")
            return go("/profil")
        user.password = hash_pw(baru)
    if user.nasabah_id:
        nasabah = db.get(Nasabah, user.nasabah_id)
        nasabah.nama = f.get("nama", "").strip()[:100] or nasabah.nama
        nasabah.alamat = f.get("alamat", "").strip()[:200]
        nasabah.no_hp = f.get("no_hp", "").strip()[:20]
        user.nama = nasabah.nama
    log(db, user, "ubah_profil", "Profil atau password diperbarui")
    db.commit()
    flash(request, "Profil berhasil diperbarui.")
    return go("/profil")


@app.get("/limit-transfer")
def limit_transfer(request: Request, q: str = "", user=Depends(require_admin), db: Session = Depends(get_db)):
    stmt = select(Nasabah).order_by(Nasabah.nama)
    if q:
        stmt = stmt.where(Nasabah.nama.ilike(f"%{q}%") | Nasabah.nik.contains(q))
    nasabah = db.scalars(stmt).all()
    limits = {x.nasabah_id: x for x in db.scalars(select(LimitTransfer)).all()}
    return page(request, "limit.html", user, tab="limit", rows=nasabah, limits=limits, q=q)


@app.post("/limit-transfer/{nasabah_id}")
async def limit_transfer_simpan(nasabah_id: int, request: Request, user=Depends(require_admin),
                                db: Session = Depends(get_db)):
    f = await request.form()
    try:
        per = max(0, rupiah(f.get("per_transaksi")))
        harian = max(0, rupiah(f.get("harian")))
    except (TypeError, ValueError):
        flash(request, "Limit tidak valid.", "err")
        return go("/limit-transfer")
    if per <= 0 or harian <= 0 or harian < per:
        flash(request, "Limit harian harus lebih besar dari atau sama dengan limit per transaksi.", "err")
        return go("/limit-transfer")
    limit = db.scalar(select(LimitTransfer).where(LimitTransfer.nasabah_id == nasabah_id))
    if limit:
        limit.per_transaksi = per
        limit.harian = harian
    else:
        db.add(LimitTransfer(nasabah_id=nasabah_id, per_transaksi=per, harian=harian))
    log(db, user, "ubah_limit", f"Nasabah #{nasabah_id}: {per}/{harian}")
    db.commit()
    flash(request, "Limit transfer berhasil diperbarui.")
    return go("/limit-transfer")


@app.get("/audit")
def audit(request: Request, pagination_page: int = 1, user=Depends(require_admin),
          db: Session = Depends(get_db)):
    total = db.scalar(select(func.count(AuditLog.id)))
    page_no, per_page, pages = halaman(pagination_page, 20, total)
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc())
                      .limit(per_page).offset((page_no - 1) * per_page)).all()
    return page(request, "audit.html", user, tab="audit", rows=rows,
                pagination={"page": page_no, "pages": pages, "per": per_page, "total": total})
