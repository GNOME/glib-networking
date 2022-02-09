#!/bin/bash

set -e

TAG="registry.gitlab.gnome.org/gnome/glib-networking/master:v19"

cd "$(dirname "$0")"

podman pull registry.fedoraproject.org/fedora:latest
podman build --build-arg HOST_USER_ID="$UID" --tag "${TAG}" --file "Dockerfile" --format=docker .

if [ "$1" = "--push" ]; then
  podman login registry.gitlab.gnome.org
  podman push $TAG
else
  podman run --rm \
      --volume "$(pwd)/..:/home/user/app" --workdir "/home/user/app" \
      --tty --interactive "${TAG}" bash
fi
