FROM fedora:33

RUN dnf update -y \
    && dnf install -y 'dnf-command(builddep)' \
    && dnf builddep -y glib-networking glib2 \
    && dnf install -y clang-analyzer \
                      libasan \
                      openssl-devel \
                      git \
                      opensc \
    && dnf clean all \
    && git clone https://gitlab.gnome.org/GNOME/glib.git \
    && pushd glib \
    && meson _build --prefix=/usr \
    && meson install -C _build \
    && popd \
    && rm -rf glib

ARG HOST_USER_ID=5555
ENV HOST_USER_ID ${HOST_USER_ID}
RUN useradd -u $HOST_USER_ID -ms /bin/bash user

USER user
WORKDIR /home/user

ENV LANG C.UTF-8
