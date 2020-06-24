FROM ubuntu:18.04

RUN apt-get update && apt-get -yy install ca-certificates

WORKDIR /usr/mobilecoin/testnet
COPY . .
CMD ["./mobilecoin-testnet.sh"]
