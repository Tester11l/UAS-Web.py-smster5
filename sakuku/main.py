import csv, hashlib, hmac, io, os, re, secrets
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import date, datetime, time, timedelta

from fastapi import Depends, FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from models import (AuditLog, BiayaAdmin, Base, JenisRekening, Kategori, Nasabah, Rekening,
                    SessionLocal, Transaksi, User, engine, now, today)

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
    seed()
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "dev-ganti-di-produksi"), max_age=60 * 60 * 8)
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
    request.session["uid"] = u.id
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
                user=Depends(require_admin), db: Session = Depends(get_db)):
    c = cfg(name)
    M = c["model"]
    stmt = select(M).order_by(M.id.desc())
    if c.get("where"):
        stmt = stmt.where(c["where"](M))
    if q:
        stmt = stmt.where(getattr(M, c["fields"][0][0]).ilike(f"%{q}%") | getattr(M, c["fields"][1][0]).ilike(f"%{q}%")
                          if len(c["fields"]) > 1 and c["fields"][1][2] == "text"
                          else getattr(M, c["fields"][0][0]).ilike(f"%{q}%"))
    item = db.get(M, edit) if edit else None
    return page(request, "master.html", user, name=name, c=c, rows=db.scalars(stmt).all(), q=q, item=item, tab=name)


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
def rekening_list(request: Request, q: str = "", user=Depends(require_user), db: Session = Depends(get_db)):
    stmt = select(Rekening).join(Nasabah).order_by(Rekening.id.desc())
    if user.role != "admin":
        stmt = stmt.where(Rekening.nasabah_id == user.nasabah_id)
    if q:
        stmt = stmt.where(Rekening.no_rekening.contains(q) | Nasabah.nama.ilike(f"%{q}%"))
    return page(request, "rekening.html", user, tab="rekening", rows=db.scalars(stmt).all(), q=q,
                nasabah=db.scalars(select(Nasabah).order_by(Nasabah.nama)).all() if user.role == "admin" else [],
                jenis=db.scalars(select(JenisRekening).order_by(JenisRekening.id)).all())


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


@app.get("/audit")
def audit(request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    return page(request, "audit.html", user, tab="audit",
                rows=db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(200)).all())
