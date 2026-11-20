# Sakuku — Mini Bank (CRUD) · FastAPI + PostgreSQL

Simulasi perbankan untuk tugas kuliah. **Jangan memasukkan data asli.**

## Akun awal
Petugas dibuat otomatis saat pertama jalan: `admin` / `admin123`
(ubah lewat env `ADMIN_USER` dan `ADMIN_PASSWORD` sebelum deploy). Nasabah mendaftar sendiri lewat halaman Register.

## Jalankan lokal
    pip install -r requirements.txt
    uvicorn main:app --reload
Lokal otomatis pakai SQLite (`sakuku.db`). Untuk memakai Neon:
    export DATABASE_URL="postgresql://user:pass@host/db?sslmode=require"

## Deploy (Neon + Render)
- Neon: salin connection string. Tabel dibuat otomatis, `schema.sql` hanya opsional.
- Render (Web Service, Free): Build `pip install -r requirements.txt`, Start `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Environment: `DATABASE_URL`, `SECRET_KEY` (string acak panjang), `ADMIN_PASSWORD`, `PYTHON_VERSION=3.12.7`

## Pemetaan ke ketentuan tugas
1. Basis data → PostgreSQL (Neon): users, nasabah, jenis_rekening, kategori_transaksi, biaya_admin, rekening, transaksi, audit_log
2. Login/register/dashboard → peran nasabah & petugas, dashboard berbeda per peran
3. File master → nasabah, jenis rekening, kategori, biaya admin, petugas (CRUD penuh)
4. File transaksi → buka rekening, setor, tarik, transfer (atomik), bekukan/tutup rekening
5. File report → mutasi (filter, cetak, CSV), saldo nasabah, transaksi harian, pendapatan biaya admin, pengeluaran per kategori
6. Hosting gratis → Neon + Render

## Aturan bisnis
- Setiap perubahan saldo = 1 baris di tabel `transaksi` (buku besar), tidak pernah hanya menimpa saldo.
- Saldo setelah transaksi tidak boleh di bawah saldo minimum jenis rekening.
- Transfer = satu transaksi database: debit, biaya, dan kredit berhasil bersama atau batal semua.
- Nasabah hanya bisa melihat dan mentransfer dari rekening miliknya sendiri.
