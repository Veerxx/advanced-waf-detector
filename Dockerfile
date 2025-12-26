FROM python:3.9-slim

LABEL maintainer="Veerxx"
LABEL version="2.0.0"
LABEL description="Advanced WAF Detection Tool"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY waf_detector.py .
COPY config/ ./config/
COPY utils/ ./utils/

# Create volume for output
VOLUME ["/app/results"]

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Create non-root user
RUN useradd -m -u 1000 wafuser
USER wafuser

# Entry point
ENTRYPOINT ["python", "waf_detector.py"]
CMD ["--help"]
