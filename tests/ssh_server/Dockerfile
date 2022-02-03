FROM ubuntu
USER root
RUN apt update && apt upgrade -y && apt install -y openssh-server

# SSH Configuration
COPY sshd_config /etc/ssh/sshd_config
COPY user-ca.pub /etc/ssh/user-ca.pub
RUN chmod 600 /etc/ssh/user-ca.pub
RUN service ssh start

# User Configuration
RUN useradd -m -d /home/testuser -s /bin/bash -g root -G sudo -u 1000 testuser 
USER 1000
RUN mkdir /home/testuser/.ssh
COPY authorized_keys /home/testuser/.ssh/authorized_keys

USER root

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
