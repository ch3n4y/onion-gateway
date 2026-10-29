FROM alpine:3.20
RUN apk add --no-cache tor
COPY torrc /etc/tor/torrc
EXPOSE 9051
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
