#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <linux/if_link.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <macros/quic.h>

#include <ebpf/interface.h>
#include <ebpf/common/macros.h>
#include <ebpf/common/structs.h>
#include <ebpf/kernel/maps.h>
#include <ebpf/kernel/services.h>

#if PRODIGY_DEBUG
#include <ebpf/kernel/debug.h>
#endif
