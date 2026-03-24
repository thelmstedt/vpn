FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    privoxy microsocks supervisor ca-certificates curl net-tools netcat-traditional \
    dnsmasq dnsutils \
&& apt-get upgrade -y \
&& apt-get autoclean -y \
&& apt-get autoremove -y \
&& rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*

EXPOSE 1080

COPY ./supervisord.conf /etc/supervisor/supervisord.conf
COPY start-dnsmasq.sh /start-dnsmasq.sh
RUN chmod +x /start-dnsmasq.sh

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]