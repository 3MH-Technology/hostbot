FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    dnsutils \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN printf "nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1\n" > /etc/resolv.conf && \
    chmod 666 /etc/resolv.conf

RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

WORKDIR /app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY --chown=user . .

ENV SERVER_PORT=7860
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:7860/health || exit 1

CMD ["python", "app.py"]
