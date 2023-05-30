#!/bin/bash
# Build libpcap using the HBB Podman image. If you don't have the
# image on your machine, build it with the image-build.sh script or
# pull it from an internal registry.
#
REPO_PATH_ABS=$(git rev-parse --show-toplevel)
podman run -it --rm --privileged -e BUILD_TOPDIR=${REPO_PATH_ABS} -v ${REPO_PATH_ABS}:${REPO_PATH_ABS} --userns=host libpcap-builder bash /inside-container-build.sh
