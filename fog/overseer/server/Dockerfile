FROM ubuntu:20.04
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get clean \
  && rm -r /var/lib/apt/lists

WORKDIR /
COPY bin/start_overseer_server /usr/local/bin/start_overseer_server

# The default port that the Fog Overseer HTTP Server runs on.
ARG DEFAULT_PORT=9090

ENV LISTEN_HOST 127.0.0.1
ENV LISTEN_PORT $DEFAULT_PORT

# Required environment variables
# INGEST_CLUSTER_URIS - comma separated list of Fog Ingest *Client* URIs.

CMD ["/usr/local/bin/start_overseer_server"]

EXPOSE $DEFAULT_PORT
