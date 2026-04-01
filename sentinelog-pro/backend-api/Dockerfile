FROM python:3.12-slim

WORKDIR /app

# Dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Installation des dépendances Python
COPY backend-api/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code et du module partagé
COPY shared/ shared/
COPY backend-api/main.py main.py

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000

CMD ["python", "main.py"]
