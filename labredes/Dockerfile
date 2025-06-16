FROM docker.io/golang:bullseye AS easy-novnc-build
WORKDIR /src
RUN go mod init build && \
    go get github.com/geek1011/easy-novnc@v1.1.0 && \
    go build -o /bin/easy-novnc github.com/geek1011/easy-novnc

FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends openbox tint2 xdg-utils \
    lxterminal hsetroot tigervnc-standalone-server supervisor && \
    rm -rf /var/lib/apt/lists

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends vim geany openssh-client \
    wget curl rsync ca-certificates apulse libpulse0 firefox-esr htop tar \
    xzip gzip bzip2 zip unzip xterm wireshark net-tools tcpdump traceroute \
    ethtool iperf nmap iproute2 iputils-ping iputils-arping dsniff \
    telnet iptables iputils-tracepath socat netcat-traditional \
    build-essential git python3-pip python3-venv python3-pyqt5.qtsvg \
    python3-pyqt5.qtwebsockets libpcap-dev python3-tk cmake libelf-dev \
    libpcap0.8-dev && \
    rm -rf /var/lib/apt/lists
    
RUN git clone https://github.com/GNS3/dynamips.git && \
    cd dynamips && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make && \
    make install && \
    cd ../.. && \
    rm -rf dynamips

RUN git clone https://github.com/GNS3/ubridge.git && \
    cd ubridge && \
    make && \
    make install && \
    cd ../ && \
    rm -rf ubridge
    
RUN git clone https://github.com/GNS3/vpcs && \
    cd vpcs/src && \
    ./mk.sh && \
    cp vpcs /usr/local/bin && \
    cd ../ && \
    rm -rf vpcs
    
RUN python3 -m venv /usr/local/gns3env
ENV PATH="/usr/local/gns3env/bin":$PATH

# RUN pip install pyqt5 && \
#     pip install gns3-server && \
#     pip install gns3-gui

COPY --from=easy-novnc-build /bin/easy-novnc /usr/local/bin/
COPY common/supervisord.conf /etc/
COPY common/menu.xml /etc/xdg/openbox/
RUN echo 'hsetroot -solid "#123456" &' >> /etc/xdg/openbox/autostart

RUN mkdir -p /etc/firefox-esr
RUN echo 'pref("browser.tabs.remote.autostart", false);' >> /etc/firefox-esr/syspref.js

RUN mkdir -p /root/.config/tint2
# COPY common/tint2rc /root/.config/tint2/

EXPOSE 8080
ENTRYPOINT ["/bin/bash", "-c", "/usr/bin/supervisord"]
