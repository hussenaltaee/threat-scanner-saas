FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    ruby-full \
    build-essential \
    libcurl4-openssl-dev \
    zlib1g-dev \
    wget \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN gem install wpscan --no-document

WORKDIR /app

COPY backend/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install --with-deps chromium

COPY . .

WORKDIR /app/backend

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]
