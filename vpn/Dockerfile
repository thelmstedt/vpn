FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
openconnect inotify-tools curl net-tools netcat-traditional dnsutils iptables \
&& apt-get update \
&& apt-get upgrade -y \
&& apt-get remove -fy \
&& apt-get autoclean -y \
&& apt-get autoremove -y \
&& rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*

ENV OPENCONNECT_AUTH_COOKIE=""
ENV OPENCONNECT_AUTH_SERVERCERT=""
ENV OPENCONNECT_AUTH_SERVER=""

COPY start-vpn.sh /start-vpn.sh

CMD ["/start-vpn.sh"]
