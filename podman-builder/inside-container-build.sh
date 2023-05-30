#!/bin/bash
# This script should only be run from inside the docker
# container. Typically you will not run this manually. It will be
# called by other scripts in here.
set -e

# Activate Holy Build Box environment.
source /hbb_exe/activate

set -x

cd ${BUILD_TOPDIR}/libpcap
./configure --prefix=/usr --enable-axellio --enable-dbus=no
make -j
