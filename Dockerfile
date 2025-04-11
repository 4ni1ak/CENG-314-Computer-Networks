
FROM archlinux:latest

WORKDIR /app

COPY network_analyzer.sh .

RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
    bash \
    wireshark-cli \
    curl \
    iproute2 \
    bind \
    bc \
    iputils \
    nmap \
    python \
    procps-ng \
    coreutils \
    which \
    && \
    pacman -Scc --noconfirm

RUN chmod +x network_analyzer.sh

EXPOSE 8000


CMD ["./network_analyzer.sh"]