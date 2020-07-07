FROM fedora:rawhide

RUN dnf update -y \
    && dnf install -y 'dnf-command(builddep)' \
    && dnf builddep -y glib-networking \
    && dnf install -y libasan openssl-devel crypto-policies-scripts \
    && dnf clean all

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user
RUN update-crypto-policies --set DEFAULT:FEDORA32

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
