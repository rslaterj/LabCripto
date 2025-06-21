# Dockerfile.S1C4
FROM ubuntu:22.04

# Instala OpenSSH server y client
RUN apt-get update \
 && apt-get install -y openssh-server openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Prepara el demonio SSH
RUN mkdir -p /var/run/sshd

# (Solo en S1) Crea el usuario 'test' con contraseña 'test'
RUN useradd -m test \
 && echo 'test:test' | chpasswd

# Habilita autenticación por contraseña
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
