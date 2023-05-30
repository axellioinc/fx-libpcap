# libpcap Portable Build Environment

### Easy-Mode

This directory defines a HBB (Holy Build Box) based Dockerfile that
will enable you to build a portable version of our libpcap library. It
does this by linking against an old version of libc. This could be
useful if you're trying to use this library with Zeek and a custom
libc, for example. Or perhaps you want to build on one distro and run
on another with an older version of libc?

If you've never run this before, you'll need to build the Podman image
on your host. You will, of course, need Podman installed on your
system to do this. You can use the script here to make that happen as
shown below. You only need to do this once for any given
host/configuration.

    ./image-build.sh

Once you have the Podman image in your local repository (from the
build command above) you can use it to build the libpcap library in a
portable fashion. You might choose to use the script in this directory
to do so.

    ./libpcap-build.sh


### Advanced Mode

You might choose to enter the HBB docker container to do more
complicated things yourself. Use something like shown below to enter
the container. You'll have to change directories, activate the hbb
toolset, and other things yourself. Use the /inside-container-build.sh
script for hints if needed.

    podman run -it --rm --privileged -v /home/linux:/home/linux --userns=host pcaputils-builder bash
