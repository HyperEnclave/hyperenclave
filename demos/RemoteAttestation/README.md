This project demonstrates how to run FAKE RemoteAttestation on hyperEnclave, which is equipped with FAKE TPM and is without the CA support. The RemoteAttestation equipped with hardware TPM and with CA support is not open source now.

The SampleCode is preinstalled in our docker image, so mount the `RemoteAttestation.sh` to the container for execution.

1. Here are instructions for starting the docker container:
```bash
# Pull the docker image
$ docker pull occlum/hyperenclave:0.27.10-hypermode-1.3.0-ubuntu20.04

# Start the container
$ cd hyperenclave
$ docker run -dt --net=host --device=/dev/hyperenclave \
                --name hyperenclave_container \
                -w /root \
                -v $(pwd)/demos:/root/hyperenclave_demos \
                occlum/hyperenclave:0.27.10-hypermode-1.3.0-ubuntu20.04 \
                bash

# Enter the container
$ docker exec -it hyperenclave_container bash
```

2. Run RemoteAttestation inside docker container:
```bash
$ cd /root/hyperenclave_demos/RemoteAttestation
$ bash RemoteAttestation.sh
Info: RemoteAttestation successfully returned.
```