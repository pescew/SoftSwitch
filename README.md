# SoftSwitch
experimental eBPF layer 2 software switch

respects and routes vlan tags with ingress filtering

to maximize performance the switching logic runs entirely in kernel-space using XDP and TC eBPF hooks. user-space program is only used to configure the switch.

XDP program will be executed by the network driver if the driver supports native XDP.  Otherwise XDP program will run in generic mode with reduced performance. in order to use native XDP mode NIC driver must support XDP_REDIRECT function.

unicast frames are handled by XDP program. broadcast frames are handed off to TC program due to XDP redirect limitations.

requires linux kernel version 5.17 or newer (bpf_loop support)

## Usage
port configuration is read from yaml or json, or can be manually defined using command line flags:

```
softswitch -port enp5s0,trunk -port enp5s0d1,80 -port enp8s0,10,70,80 -port enp8s0d1,10,trunk,xdpgeneric
```

manually configured ports are provided as comma separated strings:

first element defines the nic interface name.

first number defines the pvid/untagged vlan.

subsequent numbers define tagged vlans.

xdpMode can be set to either xdpdrv or xdpgeneric

## Building from source
requires kernel version 5.17 or newer.  required packages:

```
make clang gcc-multilib libpcap-dev linux-tools-common linux-tools-generic linux-cloud-tools-generic
```

generate vmlinux.h:

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./ebpf/include/vmlinux.h
```

make:
```
make -B
```

