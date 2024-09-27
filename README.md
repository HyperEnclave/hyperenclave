<p align="center">
    <a href="https://github.com/HyperEnclave/hyperenclave">
        <img alt="HyperEnclave Logo" src="docs/images/logo.svg" width="75%" />
    </a>
</p>
<p align="center">
    <a href="https://github.com/HyperEnclave/hyperenclave/blob/master/LICENSE">
        <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue" />
    </a>
</p>

# \*\*REPOSITORY MOVED TO A NEW LOCATION\*\*
**Note**: HyperEnclave repository has been moved to a new location: [https://github.com/asterinas/hyperenclave](https://github.com/asterinas/hyperenclave).

All development will continue there.

# Introduction to HyperEnclave

HyperEnclave is an open and cross-platform trusted execution environment which runs on heterogeneous CPU platforms but decouples its root of trust from CPU vendors. In its nature, HyperEnclave calls for a better TEE ecosystem with improved transparency and trustworthiness. HyperEnclave has been implemented on various commodity CPU platforms and deployed in real-world confidential computing workloads.


# Key features

- **Unified abstractions.** Provide unified SGX-like abstraction with virtualization hardware.

- **Controlled RoT.** RoT(Root of Trust) has been decoupled from CPU vendors and built on the trustworthy TPM.

- **Proved security.** The first commerial Rust hypervisor that has been formally verified.

- **Auditability.** The core has been open-sourced and audited by the National Authority.


# Supported CPU List
We have successfully built HyperEnclave and performed tests on the following CPUs:
## [Intel](https://www.intel.com/)
- Intel(R) Xeon(R) Gold 6342 CPU @ 2.80GHz
- Intel 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz
## [AMD](https://www.amd.com/)
- AMD EPYC 7601 64-core Processor @2.2GHz
- AMD Ryzen R3-5300G 4-core Process @4GHz
## [Hygon](https://www.hygon.cn/)
- Hygon C86 7365 24-core Processor @2.50GHz
- Hygon C86 3350 8-core Processor @2.8GHz
## [ZHAOXIN](https://www.zhaoxin.com/)
- ZHAOXIN KH-40000 @2.0/2.2GHz
- ZHAOXIN KX-6000 @3.0GHz


# Quick start

We take Intel platform as an example to show how to build HyperEnclave.

## Prerequisites

### Software version

- Ubuntu 20.04
- Linux kernel in [Supported Linux kernel version](#supported-linux-kernel-version)
- Linux kernel headers (For building the driver)
- Docker
- GCC >= 6.5

#### Supported Linux kernel version

- Linux kernel 4.19
- Linux kernel 5.4

We can check the kernel version by:
```bash
$ uname -r
```

and install the required kernel (if necessary) by:

```bash
# Download and install Linux 5.4 kernel.
$ sudo apt install wget
$ wget https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
$ chmod +x ubuntu-mainline-kernel.sh
$ sudo ./ubuntu-mainline-kernel.sh -i 5.4.0

# Reboot the system, and we need to select the kernel in grub menu.
$ sudo reboot
```

### Hardware requirements
- Intel platform which supports VMX
- The DRAM size of your platform should be greater than 8GB

## Steps

### Reserve secure memory for HyperEnclave in kernel’s command-line

Open and modify the `/etc/default/grub` file, and append the following configurations for `GRUB_CMDLINE_LINUX`:

```
memmap=4G\\\$0x100000000 intel_iommu=off intremap=off no5lvl
```


Take the new grub configuration into effect, and reboot the system:

```bash
$ sudo update-grub
$ sudo reboot
```

After reboot, check whether the modified kernel's command-line takes effect:

```bash
$ cat /proc/cmdline
```

You can see:
```
BOOT_IMAGE=/boot/vmlinuz-... root=... memmap=4G$0x100000000 intel_iommu=off intremap=off no5lvl ...
```


### Clone the repository

```bash
$ git clone https://github.com/HyperEnclave/hyperenclave.git
$ git clone https://github.com/HyperEnclave/hyperenclave-driver.git
```

### Build the HyperEnclave's driver
```bash
$ cd hyperenclave-driver
$ make
$ cd ..
```

### Build and install HyperEnclave
```bash
# Install rust toolchain 
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source $HOME/.cargo/env
$ rustup component add rust-src

# Build and install HyperEnclave
$ cd hyperenclave
$ make VENDOR=intel SME=off LOG=warn
$ make VENDOR=intel SME=off LOG=warn install
$ cd ..
```

### Start HyperEnclave

```bash
$ cd hyperenclave/scripts
$ bash start_hyperenclave.sh
$ cd ../..
```

Show the messages in kernel ring buffer by:
```bash
$ dmesg
```
And you can see:
```
...
[0] Activating hypervisor on CPU 0...
[1] Activating hypervisor on CPU 1...
[2] Activating hypervisor on CPU 2...
[3] Activating hypervisor on CPU 3...
[4] Activating hypervisor on CPU 4...
[5] Activating hypervisor on CPU 5...
[6] Activating hypervisor on CPU 6...
[7] Activating hypervisor on CPU 7...
...
```

It indicates we successfully start the HyperEnclave.

### Run TEE applications

We provide several sample TEE applications running atop of HyperEnclave. All of them are integrated into our docker image.

Here are instructions for starting the docker container:
```bash
# Pull the docker image
$ docker pull occlum/hyperenclave:0.27.10-hypermode-1.3.0-ubuntu20.04

# Start the container
$ docker run -dt --net=host --device=/dev/hyperenclave \
                --name hyperenclave_container \
                -w /root \
                occlum/hyperenclave:0.27.10-hypermode-1.3.0-ubuntu20.04 \
                bash

# Enter the container
$ docker exec -it hyperenclave_container bash
```

#### SGX SDK Samples

You can run TEE applications developed based on [Intel SGX SDK](https://github.com/intel/linux-sgx). All the SGX SDK's sample codes are preinstalled in our docker image at `/opt/intel/sgxsdk/SampleCode`. Here are two samples (Command should be done inside Docker container):

- SampleEnclave
```bash
$ cd /opt/intel/sgxsdk/SampleCode/SampleEnclave
$ make
$ ./app
Info: executing thread synchronization, please wait...
Info: SampleEnclave successfully returned.
```

- RemoteAttestation

Reference to `demos/RemoteAttestation` for more information.

#### Occlum demos

You can also run TEE applications developed based on [Occlum](https://github.com/occlum/occlum). All the Occlum demos are preinstalled in our docker image at `/root/occlum/demos`. Before having a try on them, install [enable_rdfsbase kernel module](https://github.com/occlum/enable_rdfsbase) to **make sure `fsgsbase` is enabled**.

We take `hello_c` as an example. (Command should be done inside Docker container):
```bash
$ cd /root/occlum/demos/hello_c

# Compile the user program with the Occlum toolchain
$ occlum-gcc -o hello_world hello_world.c
# Ensure the program works well outside enclave
$ ./hello_world
Hello World

# Initialize a directory as the Occlum instance, and prepare the Occlum's environment
$ mkdir occlum_instance && cd occlum_instance
$ occlum init
$ cp ../hello_world image/bin/
$ occlum build

# Run the user program inside an HyperEnclave's enclave via occlum run
$ occlum run /bin/hello_world
Hello World!
```


# Academic publications
[**USENIX ATC'22**] [HyperEnclave: An Open and Cross-platform Trusted Execution Environment.](https://www.usenix.org/conference/atc22/presentation/jia-yuekai)
Yuekai Jia, Shuang Liu, Wenhao Wang, Yu Chen, Zhengde Zhai, Shoumeng Yan, and Zhengyu He. 2022 USENIX Annual Technical Conference (USENIX ATC 22). Carlsbad, CA, Jul, 2022.

```
@inproceedings {jia2022hyperenclave,
  author = {Yuekai Jia and Shuang Liu and Wenhao Wang and Yu Chen and Zhengde Zhai and Shoumeng Yan and Zhengyu He},
  title = {{HyperEnclave}: An Open and Cross-platform Trusted Execution Environment},
  booktitle = {2022 USENIX Annual Technical Conference (USENIX ATC 22)},
  year = {2022},
  isbn = {978-1-939133-29-48},
  address = {Carlsbad, CA},
  pages = {437--454},
  url = {https://www.usenix.org/conference/atc22/presentation/jia-yuekai},
  publisher = {USENIX Association},
  month = jul,
}
```

# License
Except where noted otherwise, HyperEnclave's hypervisor is under the Apache License (Version 2.0). See the [LICENSE](./LICENSE) files for details.
