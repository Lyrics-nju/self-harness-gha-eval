FROM alpine:3.20
RUN apk add --no-cache bash curl ca-certificates
RUN curl -fsSL --retry 0 --connect-timeout 15 --max-time 90 https://github.com/ >/dev/null && echo TASK_NETWORK_OK >/task-network.ok
WORKDIR /root/probe
