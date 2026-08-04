FROM python:3.12-slim

# --- system tool-chain used by the stego/forensics pipeline -----------------
# ruby is only here for zsteg (gem install) - it can't be installed via apt.
# tshark needs debconf pre-seeding to skip its interactive "allow non-root
# capture" prompt during a non-interactive Docker build.
RUN echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections \
    && DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --no-install-recommends \
        file binutils \
        exiftool binwalk steghide foremost pngcheck xxd \
        zbar-tools \
        tshark checksec \
        ruby ruby-dev build-essential \
        whois dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && gem install zsteg --no-document

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
