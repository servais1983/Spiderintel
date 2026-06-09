FROM kalilinux/kali-rolling:latest AS kali-system

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9-dnsutils \
        ca-certificates \
        nmap \
        python3 \
        python3-pip \
        python3-venv \
        theharvester \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY . /workspace

RUN python3 -m venv /opt/spiderintel-venv \
    && /opt/spiderintel-venv/bin/python -m pip install --upgrade pip \
    && /opt/spiderintel-venv/bin/python -m pip install -e ".[dev]"

ENV PATH="/opt/spiderintel-venv/bin:${PATH}"

FROM kali-system AS kali-metasploit

RUN apt-get update \
    && apt-get install -y --no-install-recommends metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

CMD ["python", "tests/integration_metasploit.py"]

FROM kali-system AS kali-integration

CMD ["python", "tests/integration_kali.py"]
