#!/bin/bash
# Use this script to build the docker image defined in this dir - only
# need to do this once for any given host
podman build -t libpcap-builder .
