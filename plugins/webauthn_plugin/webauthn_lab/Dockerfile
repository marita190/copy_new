FROM python:3.11-slim
WORKDIR /app
RUN pip install flask webauthn
COPY app.py .
CMD ["python", "app.py"]
