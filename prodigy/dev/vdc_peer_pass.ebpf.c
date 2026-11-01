#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Linux veth's XDP_TX flush requires a peer XDP program to schedule its
 * receive ring. The provider transport passes every frame to the bridge;
 * Switchboard on the machine end remains the routing owner. */
SEC("xdp")
int vdc_peer_pass(struct xdp_md *context)
{
  (void)context;
  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
