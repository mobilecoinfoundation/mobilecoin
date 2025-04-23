# Create Docker Container

From the root of the mobilecoin repo that was downloaded to your local machine earlier, run the following

```
./mob prompt \
--publish 3200 3201 3202
```

This will download the MobileCoin base image and link your local repo as a volume in the docker container.

The ports being exposed and published are to allow services outside of the docker container, such as Full Service, to connect to the Consensus Nodes running inside of the container. If you don't intend to run services this way, feel free to omit them from the command.

Upon completion, it will put you into the docker container shell. If you would like to reconnect, or establish another connection, run the following command

```
docker exec -it <container_name> /bin/bash
```

