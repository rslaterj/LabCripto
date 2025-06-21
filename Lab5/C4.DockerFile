# Dockerfile.S1C4
FROM ubuntu:22.04

RUN apt-get update \
 && apt-get install -y openssh-server openssh-client \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd

RUN useradd -m test \
 && echo 'test:test' | chpasswd

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
