FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    python3 python3-pygame python3-cryptography python3-pytest python3-pil \
    hostapd dnsmasq-base network-manager nftables iw iproute2 systemd adduser \
    sslsplit tcpdump openssl \
    && rm -rf /var/lib/apt/lists/*
RUN printf 'path-include /usr/share/doc/gainsec-gitm/*\n' > /etc/dpkg/dpkg.cfg.d/zz-gainsec-qa-docs
