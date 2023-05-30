FROM phusion/holy-build-box-64:latest
COPY install-deps.sh /install-deps.sh
RUN bash /install-deps.sh && rm -f /install-deps.sh
COPY inside-container-build.sh /inside-container-build.sh
