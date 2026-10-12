FROM python:3.11-slim
WORKDIR /app
COPY requitxt .
RUN pip install --no-cache-dir -r requi.txt
COPY app.py .
EXPOSE 5001
CMD ["python", "app.py"]
