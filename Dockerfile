FROM python:3.10-slim

# 1. Install kubectl
RUN apt-get update && apt-get install -y curl && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    chmod +x kubectl && mv kubectl /usr/local/bin/

WORKDIR /app

# 2. Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Copy ALL code into the image (Making it self-contained)
COPY . .

# 4. Create a directory for reports (This will be our mount point)
RUN mkdir /app/reports

# Set environment variable to tell the script where to save the PDF
ENV REPORT_PATH=/app/reports

ENTRYPOINT ["python", "cli_dashboard.py"]