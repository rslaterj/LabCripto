# Dockerfile.C2
FROM ubuntu:18.10

RUN sed -i \
      -e 's|http://archive.ubuntu.com/ubuntu/|http://old-releases.ubuntu.com/ubuntu/|g' \
      -e 's|http://security.ubuntu.com/ubuntu/|http://old-releases.ubuntu.com/ubuntu/|g' \
      /etc/apt/sources.list

RUN apt-get update \
 && apt-get install -y openssh-server openssh-client \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
