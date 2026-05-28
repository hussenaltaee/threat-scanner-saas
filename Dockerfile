FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install --with-deps chromium

COPY . .

WORKDIR /app/backend

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]