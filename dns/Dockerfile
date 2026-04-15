FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    dnsmasq inotify-tools \
&& apt-get upgrade -y \
&& apt-get autoclean -y \
&& apt-get autoremove -y \
&& rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*

COPY start-dns.sh /start-dns.sh
RUN chmod +x /start-dns.sh

CMD ["/start-dns.sh"]
