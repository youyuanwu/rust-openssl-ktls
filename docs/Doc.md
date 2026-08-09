# MISC

This crate links against the system openssl, which needs to be built with
`enable-ktls`. Recent Debian/Ubuntu openssl 3.x packages have it enabled, so no
vendored build is required. Verify and load the kernel `tls` module:
```sh
# check kmod
lsmod | grep tls
sudo modprobe tls

# check the tls ulp is available
cat /proc/sys/net/ipv4/tcp_available_ulp

openssl version -a
```

If your system openssl lacks ktls, build one and point `OPENSSL_DIR` at it, for
example using vcpkg:
```sh
# remove system install 
sudo apt remove libssl-dev 
# insall from vcpkg
vcpkg install openssl --overlay-ports=vcpkg/ports/openssl
export OPENSSL_DIR="$VCPKG_ROOT/installed/x64-linux"

perl ${VCPKG_ROOT}/buildtrees/openssl/x64-linux-dbg/configdata.pm --dump | grep ktls

nm -C ${VCPKG_ROOT}/installed/x64-linux/debug/lib/libssl.a | grep SSL_connect
nm -C ${VCPKG_ROOT}/installed/x64-linux/debug/lib/libssl.a | grep BIO_get_ktls_send

nm -D /usr/lib/x86_64-linux-gnu/libssl.so | grep ktls
```

```sh
# Monitor KTLS setsockopt calls
bpftrace -e 'tracepoint:syscalls:sys_enter_setsockopt /args->optname == 0x1b/ { printf("KTLS setsockopt triggered\n"); }'

# Check KTLS statistics from OS
## Kernel KTLS statistics
cat /proc/net/tls_stat

## Network statistics including TLS offload
ss -i | grep -A 5 -B 5 tls

## Check TLS ULP (Upper Layer Protocol) support
cat /proc/sys/net/ipv4/tcp_available_ulp

## Monitor KTLS activity with bpftrace
# Monitor KTLS TX offload
bpftrace -e 'tracepoint:tcp:tcp_probe { if (@ktls[tid] > 0) printf("KTLS active on tid %d\n", tid); }'

# Monitor socket options for TLS
bpftrace -e 'tracepoint:syscalls:sys_enter_setsockopt /args->level == 6 && args->optname == 0x1f/ { printf("SOL_TLS setsockopt: level=%d optname=0x%x\n", args->level, args->optname); }'

# Check network device offload capabilities
ethtool -k eth0 | grep tls

## Trace KTLS kernel functions (if available)
# Monitor tls_push_record calls
bpftrace -e 'kprobe:tls_push_record { printf("KTLS pushing record from %s\n", comm); }'

# Monitor tls_sw_sendmsg vs hardware offload
bpftrace -e 'kprobe:tls_sw_sendmsg { @sw_count++; } kprobe:tls_device_sendmsg { @hw_count++; } END { printf("SW: %d, HW: %d\n", @sw_count, @hw_count); }'
```