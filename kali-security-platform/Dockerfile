# Kali Security Platform - Fixed Docker Configuration
FROM python:3.11-slim

# Set non-interactive to avoid prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and install basic dependencies first
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install security tools (separate layer for better caching)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Try to install additional tools (may fail on slim image)
RUN apt-get update && \
    (apt-get install -y nikto hydra sqlmap 2>/dev/null || echo "Some tools not available in slim image") && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p outputs/scans outputs/reports logs

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health').raise_for_status()" || exit 1

# Run the application
CMD ["python", "main.py"]
