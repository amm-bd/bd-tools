#!/bin/env bash
# Unload monitoring container and restart it without calling start-all so we can debug it.

eval "$(/usr/sbin/bdconfig --getallenv)"

export mon=`docker ps | grep monitor | awk '{print $1}'`
docker stop $mon; docker rm $mon
docker run -it --name=epic-monitoring-${bds_network_primaryip} --cap-add=IPC_LOCK --net=host --ulimit memlock=-1:-1 --pid=host -c 2048 -m 4GB --memory-swap -1 --volume=/proc:/hostfs/proc:ro --volume=/:/hostfs:ro,rslave --volume=/var/run/docker.sock:/var/run/docker.sock:ro --volume=/var/lib/docker:/var/lib/docker:ro --volume=/var/lib/monitoring:/var/lib/monitoring --ulimit nofile=65536 --restart=always --entrypoint 'bash' epic/monitoring:1.2


