# ==========================================
# 1. BASE IMAGE
# ==========================================
FROM python:3.9-slim

# ==========================================
# 2. KONFIGURASI ENVIRONTMENT
# ==========================================

# Mencegah Python membuat file cache (.pyc) agar image lebih bersih
ENV PYTHONDONTWRITEBYTECODE=1

# Memastikan log Python langsung dicetak ke console (STDOUT)
ENV PYTHONUNBUFFERED=1

# Mengatur Timezone server ke Asia/Jakarta (WIB)
ENV TZ=Asia/Jakarta

# Menetapkan direktori kerja utama di dalam container
WORKDIR /app

# ==========================================
# 3. INSTALASI DEPENDENSI SISTEM
# ==========================================

# Update repository dan install paket sistem yang dibutuhkan:
# - gcc        : Compiler C, wajib ada untuk install library 'bcrypt'
# - libpq-dev  : Header file PostgreSQL, wajib ada untuk 'psycopg2'
# - tzdata     : Data timezone untuk sinkronisasi jam sistem
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# ==========================================
# 4. INSTALASI APLIKASI PYTHON
# ==========================================

# Menyalin file aplikasi utama (gatekeeper.py) ke dalam container
COPY gatekeeper.py .

# Install library Python
RUN pip install --upgrade pip && \
    pip install --no-cache-dir \
    flask \
    psycopg2-binary \
    bcrypt \
    requests \
    gunicorn

# ==========================================
# 5. EKSEKUSI (RUNTIME)
# ==========================================

# Membuka port 5000 container (Port internal Flask/Gunicorn)
EXPOSE 5000

# Menjalankan aplikasi dengan Gunicorn Production Server
# Penjelasan Flag:
# -w 4               : Menggunakan 4 worker process (bisa handle request paralel)
# -b 0.0.0.0:5000    : Binding host ke semua interface pada port 5000
# --access-logfile - : Redirect access log ke terminal docker (stdout)
# --error-logfile -  : Redirect error log ke terminal docker (stderr)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "--access-logfile", "-", "--error-logfile", "-", "gatekeeper:app"]