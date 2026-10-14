FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY init_db.py .
COPY entrypoint.sh .
COPY templates/ ./templates/

RUN chmod +x entrypoint.sh

EXPOSE 5000

CMD ["./entrypoint.sh"]
