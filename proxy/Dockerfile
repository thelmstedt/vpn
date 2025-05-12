FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    privoxy microsocks supervisor ca-certificates curl net-tools netcat-traditional \
&& apt-get upgrade -y \
&& apt-get autoclean -y \
&& apt-get autoremove -y \
&& rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*

EXPOSE 1080 8118

# Set up Privoxy
RUN mkdir -p /usr/share/privoxy/templates \
    && cp -r /etc/privoxy/templates/* /usr/share/privoxy/templates/

# Copy config files
COPY ./privoxy.conf /etc/privoxy/config
COPY ./supervisord.conf /etc/supervisor/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]