FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive



RUN apt-get update \
&& apt-get install -y --no-install-recommends ca-certificates curl wireguard-tools iptables iproute2 procps dnsmasq \
&& apt-get upgrade -y \
&& apt-get autoclean -y \
&& apt-get autoremove -y \
&& rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*




COPY start-wireguard.sh /start-wireguard.sh
RUN chmod +x /start-wireguard.sh

EXPOSE 51820/udp

CMD ["/start-wireguard.sh"]
