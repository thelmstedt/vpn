FROM alpine:latest

RUN apk add --no-cache curl bash

COPY heartbeat.sh /usr/local/bin/heartbeat.sh
RUN chmod +x /usr/local/bin/heartbeat.sh

CMD ["/usr/local/bin/heartbeat.sh"]