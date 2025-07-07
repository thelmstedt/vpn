FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
openconnect curl net-tools netcat-traditional \
&& apt-get update \
&& apt-get upgrade -y \
&& apt-get remove -fy \
&& apt-get autoclean -y \
&& apt-get autoremove -y \
&& rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*

ENV OPENCONNECT_AUTH_COOKIE=""
ENV OPENCONNECT_AUTH_SERVERCERT=""
ENV OPENCONNECT_AUTH_SERVER=""

CMD openconnect --cookie=$OPENCONNECT_AUTH_COOKIE --servercert=$OPENCONNECT_AUTH_SERVERCERT --server $OPENCONNECT_AUTH_SERVER --dtls-ciphers=ALL --reconnect-timeout 60 --dtls-local-port=0 --force-dpd=30