#!/bin/bash

set -e

TAG="registry.gitlab.gnome.org/gnome/glib-networking/master:v8"

cd "$(dirname "$0")"

sudo docker build --build-arg HOST_USER_ID="$UID" --tag "${TAG}" --file "Dockerfile" .

if [ "$1" = "--push" ]; then
  sudo docker login registry.gitlab.gnome.org
  sudo docker push $TAG
else
  sudo docker run --rm \
      --volume "$(pwd)/..:/home/user/app" --workdir "/home/user/app" \
      --tty --interactive "${TAG}" bash
fi
