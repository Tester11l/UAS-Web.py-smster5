-- Skema Sakuku untuk PostgreSQL (Neon). Dibuat dari models.py.
-- Opsional: aplikasi membuat tabel sendiri saat pertama dijalankan.

CREATE TABLE IF NOT EXISTS biaya_admin (
	id SERIAL NOT NULL, 
	tipe VARCHAR(20) NOT NULL, 
	nominal BIGINT NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (tipe)
);

CREATE TABLE IF NOT EXISTS jenis_rekening (
	id SERIAL NOT NULL, 
	nama VARCHAR(50) NOT NULL, 
	saldo_min BIGINT NOT NULL, 
	keterangan VARCHAR(200) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (nama)
);

CREATE TABLE IF NOT EXISTS kategori_transaksi (
	id SERIAL NOT NULL, 
	nama VARCHAR(50) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (nama)
);

CREATE TABLE IF NOT EXISTS nasabah (
	id SERIAL NOT NULL, 
	nik VARCHAR(20) NOT NULL, 
	nama VARCHAR(100) NOT NULL, 
	alamat VARCHAR(200) NOT NULL, 
	no_hp VARCHAR(20) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (nik)
);

CREATE TABLE IF NOT EXISTS rekening (
	id SERIAL NOT NULL, 
	no_rekening VARCHAR(20) NOT NULL, 
	nasabah_id INTEGER NOT NULL, 
	jenis_id INTEGER NOT NULL, 
	saldo BIGINT NOT NULL, 
	status VARCHAR(10) NOT NULL, 
	dibuka DATE NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (no_rekening), 
	FOREIGN KEY(nasabah_id) REFERENCES nasabah (id), 
	FOREIGN KEY(jenis_id) REFERENCES jenis_rekening (id)
);

CREATE TABLE IF NOT EXISTS users (
	id SERIAL NOT NULL, 
	username VARCHAR(50) NOT NULL, 
	nama VARCHAR(100) NOT NULL, 
	password VARCHAR(200) NOT NULL, 
	role VARCHAR(10) NOT NULL, 
	nasabah_id INTEGER, 
	totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
	totp_secret VARCHAR(256),
	totp_pending_secret VARCHAR(256),
	totp_pending_at TIMESTAMP WITHOUT TIME ZONE,
	totp_recovery_codes VARCHAR(2000),
	PRIMARY KEY (id), 
	UNIQUE (username), 
	FOREIGN KEY(nasabah_id) REFERENCES nasabah (id)
);

CREATE TABLE IF NOT EXISTS audit_log (
	id SERIAL NOT NULL, 
	waktu TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	user_id INTEGER, 
	aksi VARCHAR(40) NOT NULL, 
	detail VARCHAR(300) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS transaksi (
	id SERIAL NOT NULL, 
	waktu TIMESTAMP WITHOUT TIME ZONE NOT NULL, 
	rekening_id INTEGER NOT NULL, 
	tipe VARCHAR(20) NOT NULL, 
	jumlah BIGINT NOT NULL, 
	saldo_akhir BIGINT NOT NULL, 
	kategori_id INTEGER, 
	lawan_id INTEGER, 
	keterangan VARCHAR(200) NOT NULL, 
	user_id INTEGER, 
	PRIMARY KEY (id), 
	FOREIGN KEY(rekening_id) REFERENCES rekening (id), 
	FOREIGN KEY(kategori_id) REFERENCES kategori_transaksi (id), 
	FOREIGN KEY(lawan_id) REFERENCES rekening (id), 
	FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS pengajuan_rekening (
	id SERIAL NOT NULL,
	nasabah_id INTEGER NOT NULL,
	jenis_id INTEGER NOT NULL,
	status VARCHAR(10) NOT NULL,
	catatan VARCHAR(300) NOT NULL,
	dibuat TIMESTAMP WITHOUT TIME ZONE NOT NULL,
	diproses TIMESTAMP WITHOUT TIME ZONE,
	petugas_id INTEGER,
	PRIMARY KEY (id),
	FOREIGN KEY(nasabah_id) REFERENCES nasabah (id),
	FOREIGN KEY(jenis_id) REFERENCES jenis_rekening (id),
	FOREIGN KEY(petugas_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS limit_transfer (
	id SERIAL NOT NULL,
	nasabah_id INTEGER NOT NULL,
	per_transaksi BIGINT NOT NULL,
	harian BIGINT NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (nasabah_id),
	FOREIGN KEY(nasabah_id) REFERENCES nasabah (id)
);
