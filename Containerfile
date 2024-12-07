FROM scratch

LABEL org.opencontainers.image.source https://github.com/Marco98/godnsproxy
ENTRYPOINT ["/godnsproxy"]

COPY godnsproxy /godnsproxy
