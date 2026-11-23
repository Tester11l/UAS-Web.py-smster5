import os
from datetime import date, datetime, timedelta, timezone
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

WIB = timezone(timedelta(hours=7))


def now() -> datetime:
    return datetime.now(WIB).replace(tzinfo=None)


def today() -> date:
    return now().date()


url = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_JTevSOKdj3R6@ep-ancient-wind-b305j5ix-pooler.c-4.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require")
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql+psycopg2://", 1)
elif url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

engine = create_engine(url, pool_pre_ping=True,
                       connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


# ================= FILE MASTER =================
class Nasabah(Base):
    __tablename__ = "nasabah"
    id: Mapped[int] = mapped_column(primary_key=True)
    nik: Mapped[str] = mapped_column(String(20), unique=True)
    nama: Mapped[str] = mapped_column(String(100))
    alamat: Mapped[str] = mapped_column(String(200), default="")
    no_hp: Mapped[str] = mapped_column(String(20), default="")


class User(Base):  # login: role 'nasabah' atau 'admin' (petugas/teller)
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    nama: Mapped[str] = mapped_column(String(100))
    password: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(10), default="nasabah")
    nasabah_id: Mapped[int | None] = mapped_column(ForeignKey("nasabah.id"), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_secret: Mapped[str | None] = mapped_column(String(256), nullable=True)
    totp_pending_secret: Mapped[str | None] = mapped_column(String(256), nullable=True)
    totp_pending_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    totp_recovery_codes: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    nasabah: Mapped[Nasabah | None] = relationship()


class JenisRekening(Base):
    __tablename__ = "jenis_rekening"
    id: Mapped[int] = mapped_column(primary_key=True)
    nama: Mapped[str] = mapped_column(String(50), unique=True)
    saldo_min: Mapped[int] = mapped_column(BigInteger, default=0)
    keterangan: Mapped[str] = mapped_column(String(200), default="")


class Kategori(Base):
    __tablename__ = "kategori_transaksi"
    id: Mapped[int] = mapped_column(primary_key=True)
    nama: Mapped[str] = mapped_column(String(50), unique=True)


class BiayaAdmin(Base):
    __tablename__ = "biaya_admin"
    id: Mapped[int] = mapped_column(primary_key=True)
    tipe: Mapped[str] = mapped_column(String(20), unique=True)  # setor | tarik | transfer
    nominal: Mapped[int] = mapped_column(BigInteger, default=0)


# ================= FILE TRANSAKSI =================
class Rekening(Base):
    __tablename__ = "rekening"
    id: Mapped[int] = mapped_column(primary_key=True)
    no_rekening: Mapped[str] = mapped_column(String(20), unique=True)
    nasabah_id: Mapped[int] = mapped_column(ForeignKey("nasabah.id"))
    jenis_id: Mapped[int] = mapped_column(ForeignKey("jenis_rekening.id"))
    saldo: Mapped[int] = mapped_column(BigInteger, default=0)
    status: Mapped[str] = mapped_column(String(10), default="aktif")  # aktif | beku | tutup
    dibuka: Mapped[date] = mapped_column(default=today)
    nasabah: Mapped[Nasabah] = relationship()
    jenis: Mapped[JenisRekening] = relationship()


class Transaksi(Base):  # buku besar: setiap perubahan saldo = 1 baris
    __tablename__ = "transaksi"
    id: Mapped[int] = mapped_column(primary_key=True)
    waktu: Mapped[datetime] = mapped_column(DateTime, default=now)
    rekening_id: Mapped[int] = mapped_column(ForeignKey("rekening.id"))
    tipe: Mapped[str] = mapped_column(String(20))  # setor|tarik|transfer_keluar|transfer_masuk|biaya
    jumlah: Mapped[int] = mapped_column(BigInteger)  # + masuk, - keluar
    saldo_akhir: Mapped[int] = mapped_column(BigInteger)
    kategori_id: Mapped[int | None] = mapped_column(ForeignKey("kategori_transaksi.id"), nullable=True)
    lawan_id: Mapped[int | None] = mapped_column(ForeignKey("rekening.id"), nullable=True)
    keterangan: Mapped[str] = mapped_column(String(200), default="")
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    rekening: Mapped[Rekening] = relationship(foreign_keys=[rekening_id])
    lawan: Mapped[Rekening | None] = relationship(foreign_keys=[lawan_id])
    kategori: Mapped[Kategori | None] = relationship()
    pelaku: Mapped[User | None] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    waktu: Mapped[datetime] = mapped_column(DateTime, default=now)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    aksi: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str] = mapped_column(String(300), default="")
    user: Mapped[User | None] = relationship()


class PengajuanRekening(Base):
    __tablename__ = "pengajuan_rekening"
    id: Mapped[int] = mapped_column(primary_key=True)
    nasabah_id: Mapped[int] = mapped_column(ForeignKey("nasabah.id"))
    jenis_id: Mapped[int] = mapped_column(ForeignKey("jenis_rekening.id"))
    status: Mapped[str] = mapped_column(String(10), default="menunggu")  # menunggu | disetujui | ditolak
    catatan: Mapped[str] = mapped_column(String(300), default="")
    dibuat: Mapped[datetime] = mapped_column(DateTime, default=now)
    diproses: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    petugas_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    nasabah: Mapped[Nasabah] = relationship()
    jenis: Mapped[JenisRekening] = relationship()
    petugas: Mapped[User | None] = relationship()


class LimitTransfer(Base):
    __tablename__ = "limit_transfer"
    id: Mapped[int] = mapped_column(primary_key=True)
    nasabah_id: Mapped[int] = mapped_column(ForeignKey("nasabah.id"), unique=True)
    per_transaksi: Mapped[int] = mapped_column(BigInteger, default=10_000_000)
    harian: Mapped[int] = mapped_column(BigInteger, default=50_000_000)
    nasabah: Mapped[Nasabah] = relationship()
