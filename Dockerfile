FROM python:3.13-alpine

WORKDIR /app
COPY app.py /app/app.py
COPY migrate_sqlite.py /app/migrate_sqlite.py
COPY migrations /app/migrations
RUN pip install --no-cache-dir "psycopg[binary]>=3.2" \
    && chmod -R a+rX /app \
    && addgroup -S syslog && adduser -S -G syslog -u 10001 syslog

ENV WEB_HOST=0.0.0.0 WEB_PORT=8085 PYTHONUNBUFFERED=1
EXPOSE 8085/tcp
EXPOSE 514/udp
USER syslog
ENTRYPOINT ["python3", "/app/app.py"]
