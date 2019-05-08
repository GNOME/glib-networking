#!/bin/bash

set -e

TAG="registry.gitlab.gnome.org/gnome/glib-networking/master:v3"

cd "$(dirname "$0")"

# Workaround for error when running with sudo:
#
#Step 5/8 : RUN useradd -u $HOST_USER_ID -ms /bin/bash user
# ---> Running in 2ac7b00c2788
#useradd: UID 0 is not unique
docker build --build-arg HOST_USER_ID=1000 --tag "${TAG}" --file "Dockerfile" .
#docker build --build-arg HOST_USER_ID="$UID" --tag "${TAG}" --file "Dockerfile" .

if [ "$1" = "--push" ]; then
  docker login registry.gitlab.gnome.org
  docker push $TAG
else
  docker run --rm \
      --volume "$(pwd)/..:/home/user/app" --workdir "/home/user/app" \
      --tty --interactive "${TAG}" bash
fi
