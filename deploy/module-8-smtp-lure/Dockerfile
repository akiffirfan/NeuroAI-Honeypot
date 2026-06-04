FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir psycopg2-binary redis
COPY src/smtp_lure.py .
CMD ["python3", "smtp_lure.py"]
