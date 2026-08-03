FROM python:3.13-alpine

WORKDIR /app
COPY app.py /app/app.py

# A non-root user cannot bind standard syslog port 514. The container runs as root,
# but no shell or package manager is needed at runtime.
ENV DATA_DIR=/data WEB_HOST=0.0.0.0 WEB_PORT=8085 PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8085/tcp
EXPOSE 514/udp
ENTRYPOINT ["python3", "/app/app.py"]
