FROM python:3.12-slim

WORKDIR /app

# Installation des dépendances Python
COPY data-processor/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code et du module partagé
COPY shared/ shared/
COPY data-processor/main.py main.py

CMD ["python", "main.py"]
