FROM debian:13
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config libnftables-dev libjson-c-dev libsystemd-dev libnl-route-3-dev libcurl4-openssl-dev \
    systemd systemd-sysv dbus openssh-server sshpass python3 iproute2 nftables \
    unattended-upgrades ca-certificates debhelper && rm -rf /var/lib/apt/lists/*
COPY . /src
RUN cd /src && dpkg-buildpackage -us -uc -b && \
    apt-get install -y /command-center_2.1.0_*.deb /command-center-shortcut_2.1.0_all.deb && \
    test ! -L /etc/systemd/system/multi-user.target.wants/command-center.service && \
    test ! -L /etc/systemd/system/multi-user.target.wants/command-center-guard.service && \
    systemctl enable ssh.service && \
    useradd -m cmtest && echo 'cmtest:correct-test-password' | chpasswd && \
    printf 'Port 2222\nPasswordAuthentication yes\nUsePAM no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/90-cm-test.conf && \
    rm -f /usr/sbin/policy-rc.d
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
