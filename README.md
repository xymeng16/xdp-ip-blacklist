# XDP-IP-Blocker

This is a high perofrmance ip-based net packet blocker leveraging XDP in Linux.

## Quick Start

This repository depends on *libbpf*, *llvm*, *clang* and *libelf*. Before statring, you need to have them in your machine.

[libbpf](https://github.com/libbpf/libbpf/) is (to be) included as a git submodule. After cloning this repository, please run the command
```shell
git submodule update --init
```

*llvm* and *clang* compiles our restricted-C programs into BPF-byte-code, which is stored in an ELF object file (*libelf*), that is loaded by *libbpf* into the kernel via the *bpf* syscall.

To install those dependencies, please follow the below instructions or make it by yourself if the Linux distribution you are using is not included.

### Arch Linux
- Mandatory
```shell
sudo pacman -S clang llvm elfutils libelf libpcap perf
```
- Optional (for debugging and profiling purpose)
```shell
sudo pacman -S bpf tcpdump ethtool
```