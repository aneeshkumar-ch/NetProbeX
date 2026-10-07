FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    HEADLESS=1

# Install system network tools including nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iproute2 \
    procps \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Ensure reports directory exists
RUN mkdir -p /app/reports /app/reports/data /app/reports/samples

EXPOSE 8765

CMD ["uvicorn", "dashboard:app", "--host", "0.0.0.0", "--port", "8765"]
