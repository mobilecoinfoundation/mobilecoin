FROM ubuntu:20.04
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get clean \
  && rm -r /var/lib/apt/lists

WORKDIR /
COPY bin/start_overseer_server /usr/local/bin/start_overseer_server

ENV OVERSEER_LISTEN_HOST 0.0.0.0

# Required environment variables
# INGEST_CLUSTER_URIS - comma separated list of Fog Ingest *Client* URIs.

CMD ["/usr/local/bin/fog_overseer_server"]

EXPOSE 9090
