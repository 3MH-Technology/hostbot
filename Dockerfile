FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a user for Hugging Face (UID 1000 is required)
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

WORKDIR /app

# Copy requirements first for better caching
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy all files with correct ownership
COPY --chown=user . .

# Hugging Face uses port 7860 by default
ENV SERVER_PORT=7860
EXPOSE 7860

CMD ["python", "app.py"]
