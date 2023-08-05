// uncomment this to get prints at /sys/kernel/debug/tracing/trace
// #define DEBUG

#define MAX_IFACES 80
#define FDB_MAX_AGE_NS 300000000000 // 5 minutes in nanoseconds

#define ETH_P_8021Q 0x8100  /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88a8 // QinQ 802.1ad TPID
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define AF_INET 2   /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/

#include "vmlinux.h"
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <limits.h>

#define to64l(arr) (((__u64)(((__u8 *)(arr))[0]) << 0) +  \
                    ((__u64)(((__u8 *)(arr))[1]) << 8) +  \
                    ((__u64)(((__u8 *)(arr))[2]) << 16) + \
                    ((__u64)(((__u8 *)(arr))[3]) << 24) + \
                    ((__u64)(((__u8 *)(arr))[4]) << 32) + \
                    ((__u64)(((__u8 *)(arr))[5]) << 40))

__u64 toUnsigned64(const void *arr)
{
    return to64l(arr);
}

struct fdb_key
{
    __u64 mac;
    __u16 vlan;
} __attribute__((packed));

struct fdb_val
{
    __u16 iface_index;
    __u64 ktimestamp;
    _Bool tagged;
} __attribute__((packed));

struct port_cfg
{
    __u16 if_index;
    __u16 pvid;
    // __u16 vlan_bitmask[256];
    __u64 vlan_bitmask[64];
    __u8 mac[6];
    __u16 transparent;
    __u16 ingress_filtering;
    __u16 hook_drop;
    __u16 hook_egress;
    __u16 tap;
} __attribute__((packed));

volatile const struct port_cfg PORT_CFG;
volatile const __u8 PORT_COUNT;
volatile const struct port_cfg PORTS_CFG_BY_IDX[MAX_IFACES];

volatile const __u8 PORTS_IDX[MAX_IFACES];
volatile const __u8 STATS_ENABLED;

#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */
#define VLAN_HDR_SZ 4        /* bytes */

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    // __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fdb_key);
    __type(value, struct fdb_val);
    __uint(max_entries, 1024);
    // __uint(map_flags, BPF_F_NO_COMMON_LRU);
    // __uint(map_flags, BPF_F_NO_COMMON_LRU | BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} Map_fdb_xdp SEC(".maps");

struct traffic_key
{
    __u32 src_ipv4;
    __u32 dst_ipv4;
    __u16 vlan;
    __u16 proto_l2;
    __u16 proto_l3;
    __u16 target_if_index;
} __attribute__((packed));

struct traffic_stats
{
    __u64 timestamp;
    __u8 tagged;
    __u16 size;

    __u64 rx_dropped_bytes;
    __u64 rx_dropped_packets;
    __u64 rx_passed_bytes;
    __u64 rx_passed_packets;
    __u64 rx_redirected_bytes;
    __u64 rx_redirected_packets;

} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct traffic_key); // ipv4
    __type(value, struct traffic_stats);
    __uint(max_entries, 32000);
    __uint(map_flags, BPF_F_NO_COMMON_LRU);
} Map_stats_traffic SEC(".maps");

struct xdp_stats
{
    __u64 rx_dropped_bytes;
    __u64 rx_dropped_packets;
    __u64 rx_passed_bytes;
    __u64 rx_passed_packets;
    __u64 rx_redirected_bytes;
    __u64 rx_redirected_packets;
    __u64 rx_last_timestamp;

    __u64 tx_redirected_bytes;
    __u64 tx_redirected_packets;
    __u64 tx_last_timestamp;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __type(value, struct xdp_stats);
    __uint(max_entries, MAX_IFACES); // todo - change max_ifaces
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} Map_stats_xdp SEC(".maps");

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx, struct ethhdr *eth, int vlid)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr eth_cpy;
    struct vlan_hdr *vlh;

    /* First copy the original Ethernet header */
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    /* Then add space in front of the packet */
    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
        return -1;

    /* Need to re-evaluate data_end and data after head adjustment, and
     * bounds check, even though we know there is enough space (as we
     * increased it).
     */
    data_end = (void *)(long)ctx->data_end;
    eth = (void *)(long)ctx->data;

    if (eth + 1 > data_end)
        return -1;

    /* Copy back Ethernet header in the right place, populate VLAN tag with
     * ID and proto, and set outer Ethernet header to VLAN type.
     */
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

    vlh = (void *)(eth + 1);

    if (vlh + 1 > data_end)
        return -1;

    vlh->h_vlan_TCI = bpf_htons(vlid);
    vlh->h_vlan_encapsulated_proto = eth->h_proto;

    eth->h_proto = bpf_htons(ETH_P_8021Q);
    return 0;
}

static __always_inline const struct port_cfg *get_port_cfg_by_idx(__u32 idx)
{
    if (idx < MAX_IFACES)
    {
        return &PORTS_CFG_BY_IDX[idx];
    }
    bpf_printk("[get_port_cfg_by_idx] unable to get port_cfg by idx: %d, using port_cfg instead", idx);
    return &PORT_CFG;
}

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} Map_jump_table_xdp SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 7);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} Map_jump_table_tc SEC(".maps");

#define HANDLE_UNTAGGED 1
#define HANDLE_TAGGED 2
#define HANDLE_UNTAGGED_B 3
#define HANDLE_TAGGED_B 4
#define HOOK_DROP_TC 5
#define HOOK_EGRESS_TC 6

#define HOOK_DROP_XDP 1
#define HOOK_EGRESS_XDP 2

SEC("tc/hook_drop_tc")
int hook_drop_tc(struct __sk_buff *ctx)
{
    bpf_printk("[hook_drop_tc] Called... Dropping");
    return TC_ACT_SHOT;
}

SEC("tc/hook_egress_tc")
int hook_egress_tc(struct __sk_buff *ctx)
{
    bpf_printk("[hook_egress_tc] Called... Dropping");
    return TC_ACT_SHOT;
}

SEC("tc/tail_call1")
int tail_call1(struct __sk_buff *ctx)
{
    __u32 *idx = (__u32 *)&(ctx->ifindex);
    const struct port_cfg *config = get_port_cfg_by_idx(*idx);

    _Bool tail = 0;
    for (__u8 i = 0; i < MAX_IFACES; ++i)
    {
        if (i >= PORT_COUNT)
        {
            break;
        }
        else if (*idx == PORTS_IDX[i])
        {
            continue;
        }
        const struct port_cfg *cfg = get_port_cfg_by_idx(PORTS_IDX[i]);
        if (cfg->pvid == config->pvid)
        {
            if (cfg->tap)
            {
                bpf_clone_redirect(ctx, cfg->if_index, BPF_F_INGRESS);
            }
            else
            {
                bpf_clone_redirect(ctx, cfg->if_index, 0);
            }
        }
        else
        {
            tail = 1;
        }
    }
    if (tail)
    {
        bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_UNTAGGED_B);
    }

    if (config->hook_drop)
    {
        bpf_tail_call(ctx, &Map_jump_table_tc, HOOK_DROP_TC);
    }
    return TC_ACT_SHOT;
}

SEC("tc/tail_call1B")
int tail_call1B(struct __sk_buff *ctx)
{
    __u32 *idx = (__u32 *)&(ctx->ifindex);
    const struct port_cfg *config = get_port_cfg_by_idx(*idx);

    bpf_skb_vlan_push(ctx, bpf_htons(ETH_P_8021Q), config->pvid);

    if (config->pvid > 4094)
    {
        return TC_ACT_SHOT;
    }

    __u8 section = config->pvid / 64;
    __u64 offset_bitmask = 1 << (config->pvid % 64);

    for (__u8 i = 0; i < MAX_IFACES; ++i)
    {
        if (i >= PORT_COUNT)
        {
            break;
        }
        else if (*idx == PORTS_IDX[i])
        {
            continue;
        }
        const struct port_cfg *cfg = get_port_cfg_by_idx(PORTS_IDX[i]);
        if (cfg->pvid == config->pvid)
        {
            continue;
        }
        else if (cfg->vlan_bitmask[section] & offset_bitmask)
        {
            if (cfg->tap)
            {
                bpf_clone_redirect(ctx, cfg->if_index, BPF_F_INGRESS);
            }
            else
            {
                bpf_clone_redirect(ctx, cfg->if_index, 0);
            }
        }
    }

    if (config->hook_drop)
    {
        bpf_tail_call(ctx, &Map_jump_table_tc, HOOK_DROP_TC);
    }
    return TC_ACT_SHOT;
}

SEC("tc/tail_call2")
int tail_call2(struct __sk_buff *ctx)
{
    __u32 *idx = (__u32 *)&(ctx->ifindex);

    __u32 *tci = (__u32 *)&(ctx->vlan_tci);
    __u16 vlan = *tci & VLAN_VID_MASK;

    __u8 section = vlan / 64;
    __u64 offset_bitmask = 1 << (vlan % 64);

    _Bool tail = 0;
    for (__u8 i = 0; i < MAX_IFACES; ++i)
    {
        if (i >= PORT_COUNT)
        {
            break;
        }
        else if (*idx == PORTS_IDX[i])
        {
            continue;
        }
        const struct port_cfg *cfg = get_port_cfg_by_idx(PORTS_IDX[i]);
        if (cfg->pvid == vlan)
        {
            tail = 1;
            continue;
        }
        else if (cfg->vlan_bitmask[section] & offset_bitmask)
        {
            if (cfg->tap)
            {
                bpf_clone_redirect(ctx, cfg->if_index, BPF_F_INGRESS);
            }
            else
            {
                bpf_clone_redirect(ctx, cfg->if_index, 0);
            }
        }
    }
    if (tail)
    {
        bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_TAGGED_B);
    }

    const struct port_cfg *config = get_port_cfg_by_idx(*idx);
    if (config->hook_drop)
    {
        bpf_tail_call(ctx, &Map_jump_table_tc, HOOK_DROP_TC);
    }
    return TC_ACT_SHOT;
}

SEC("tc/tail_call2B")
int tail_call2B(struct __sk_buff *ctx)
{
    __u32 *idx = (__u32 *)&(ctx->ifindex);

    __u32 *tci = (__u32 *)&(ctx->vlan_tci);
    __u16 vlan = *tci & VLAN_VID_MASK;

    bpf_skb_vlan_pop(ctx);

    for (__u8 i = 0; i < MAX_IFACES; ++i)
    {
        if (i >= PORT_COUNT)
        {
            break;
        }
        else if (*idx == PORTS_IDX[i])
        {
            continue;
        }
        const struct port_cfg *cfg = get_port_cfg_by_idx(PORTS_IDX[i]);
        if (cfg->pvid == vlan)
        {
            if (cfg->tap)
            {
                bpf_clone_redirect(ctx, cfg->if_index, BPF_F_INGRESS);
            }
            else
            {
                bpf_clone_redirect(ctx, cfg->if_index, 0);
            }
        }
    }

    const struct port_cfg *config = get_port_cfg_by_idx(*idx);
    if (config->hook_drop)
    {
        bpf_tail_call(ctx, &Map_jump_table_tc, HOOK_DROP_TC);
    }
    return TC_ACT_SHOT;
}

SEC("tc/Prog_tc")
int Prog_tc(struct __sk_buff *ctx)
{

    __u32 *idx = (__u32 *)&(ctx->ifindex);
    const struct port_cfg *config = get_port_cfg_by_idx(*idx);

    if (config->transparent > 0)
    {
        void *data = (void *)(unsigned long)ctx->data;         // pointer to first byte of packet data
        void *data_end = (void *)(unsigned long)ctx->data_end; // pointer to byte after the last byte of packet data

        struct ethhdr *eth_header = data;
        if ((void *)eth_header + sizeof(*eth_header) > data_end)
        {
            bpf_printk("[TC] DROPPING SHORT PACKET");
            if (config->hook_drop)
            {
                bpf_tail_call(ctx, &Map_jump_table_tc, HOOK_DROP_TC);
            }
            return TC_ACT_SHOT;
        }

        __u64 dstMAC = toUnsigned64(eth_header->h_dest);
        __u64 self_mac64 = toUnsigned64(config->mac);

        if (dstMAC == self_mac64)
        {
            bpf_printk("[TC] dstMAC MATCH self_mac !");
            // return TC_ACT_OK;
        }
    }

    bpf_set_hash(ctx, bpf_get_prandom_u32()); // random hash... attempt to spread load across all cpus

    ////// TAIL CALL
    switch (ctx->vlan_proto)
    {
    case bpf_htons(ETH_P_8021Q):
        bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_TAGGED);
        break;
    case bpf_htons(ETH_P_8021AD):
        bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_TAGGED);
        break;
    default:
        bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_UNTAGGED);
    }
    if (config->hook_drop)
    {
        bpf_tail_call(ctx, &Map_jump_table_tc, HOOK_DROP_TC);
    }
    return TC_ACT_SHOT;
}

SEC("tc/Prog_egress_tc")
int Prog_egress_tc(struct __sk_buff *ctx)
{
    __u32 *idx = (__u32 *)&(ctx->ifindex);
    const struct port_cfg *config = get_port_cfg_by_idx(*idx);

    struct fdb_key dst_key = {0};
    dst_key.vlan = config->pvid;

    __u16 PKT_IS_TAGGED = 0;
    switch (ctx->vlan_proto)
    {
    case bpf_htons(ETH_P_8021Q):
        PKT_IS_TAGGED = 1;
        dst_key.vlan = ctx->vlan_tci & VLAN_VID_MASK;

        if (dst_key.vlan < 1 || dst_key.vlan > 4094)
        {
            bpf_printk("[TC_EGRESS(%d)] Dropping malformed packet VLAN out of range (1-4094): VLAN#%d", config->if_index, dst_key.vlan);
            return TC_ACT_SHOT;
        }

        if (config->ingress_filtering == 1)
        {
            _Bool accept = 0;
            if (dst_key.vlan == config->pvid)
            {
                accept = 1;
            }
            else
            {
                __u8 section = dst_key.vlan / 64;
                __u64 offset_bitmask = 1 << (dst_key.vlan % 64);
                if (config->vlan_bitmask[section] & offset_bitmask)
                {
                    accept = 1;
                }
            }
            if (accept == 0)
            {
                bpf_printk("[TC_EGRESS] Dropping unaccepted VLAN (%d) on PORT %d", dst_key.vlan, config->if_index);
                return TC_ACT_SHOT;
            }
        }
        break;
    case bpf_htons(ETH_P_8021AD):
        PKT_IS_TAGGED = 1;
        dst_key.vlan = ctx->vlan_tci & VLAN_VID_MASK;
        bpf_printk("[TC_EGRESS] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! TODO - DROPPING QinQ 802.1ad VLAN PACKET!");
        return TC_ACT_SHOT;
        break;
    default:
        dst_key.vlan = config->pvid;
    }

    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;
    bpf_printk("[TC_EGRESS] frame size = %d", data_end - data);

    struct ethhdr *eth_header = data;
    __u16 nh_off = sizeof(*eth_header);

    if (data + nh_off > data_end)
    {
        bpf_printk("[TC_EGRESS] Dropping malformed (short) packet 1");
        return TC_ACT_SHOT;
    }

    struct fdb_key src_key = {0};
    src_key.mac = toUnsigned64(eth_header->h_source);

    src_key.vlan = dst_key.vlan; // todo change vlan here?

    struct fdb_val val_src = {.iface_index = config->if_index, .tagged = PKT_IS_TAGGED};
    val_src.ktimestamp = bpf_ktime_get_boot_ns();

    bpf_map_update_elem(&Map_fdb_xdp, &src_key, &val_src, BPF_ANY);

    dst_key.mac = toUnsigned64(eth_header->h_dest);
    if (eth_header->h_dest[0] == 0xff)
    {
        bpf_printk("[TC_EGRESS] HANDLE BROADCAST FRAME 1, tagged: %d", PKT_IS_TAGGED);
        if (PKT_IS_TAGGED)
        {
            bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_TAGGED);
        }
        else
        {
            bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_UNTAGGED);
        }

        return TC_ACT_SHOT;
    }

    __u64 self_mac64 = toUnsigned64(config->mac);
    if (dst_key.mac == self_mac64)
    {
        bpf_printk("[TC_EGRESS] DEST MAC MATCHES SELF MAC ??? Dropping");
        return TC_ACT_SHOT;
    }

    struct fdb_val *entry = bpf_map_lookup_elem(&Map_fdb_xdp, &dst_key);
    if (!entry)
    {
        bpf_printk("[TC_EGRESS] HANDLE BROADCAST FRAME 2, tagged: %d", PKT_IS_TAGGED);
        if (PKT_IS_TAGGED)
        {
            bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_TAGGED);
        }
        else
        {
            bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_UNTAGGED);
        }
        return TC_ACT_SHOT;
    }
    else if (val_src.ktimestamp > entry->ktimestamp + FDB_MAX_AGE_NS || entry->ktimestamp > val_src.ktimestamp)
    {
        bpf_map_delete_elem(&Map_fdb_xdp, &dst_key);
        bpf_printk("[TC_EGRESS] HANDLE BROADCAST FRAME 3, tagged: %d", PKT_IS_TAGGED);
        if (PKT_IS_TAGGED)
        {
            bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_TAGGED);
        }
        else
        {
            bpf_tail_call(ctx, &Map_jump_table_tc, HANDLE_UNTAGGED);
        }
        return TC_ACT_SHOT;
    }
    else if (entry->tagged && PKT_IS_TAGGED == 0)
    {
        bpf_printk("[TC_EGRESS] VLAN PUSH");
        bpf_skb_vlan_push(ctx, bpf_htons(ETH_P_8021Q), dst_key.vlan);
    }
    else if (!entry->tagged && PKT_IS_TAGGED > 0)
    {
        bpf_printk("[TC_EGRESS] VLAN POP");
        bpf_skb_vlan_pop(ctx);
    }

    return bpf_redirect(entry->iface_index, 0);
}

// github.com/Nat-Lab/xdp-router/blob/main/router.c
// helper: decr ttl by 1 for IP and IPv6
static inline void _decr_ttl(__u16 proto, void *h)
{
    if (proto == ETH_P_IP)
    {
        struct iphdr *ip = h;
        __u32 c = ip->check;
        c += bpf_htons(0x0100);
        ip->check = (__u16)(c + (c >= 0xffff));
        --ip->ttl;
    }
    else if (proto == ETH_P_IPV6)
        --((struct ipv6hdr *)h)->hop_limit;
}

SEC("xdp/hook_route_xdp")
int hook_route_xdp(struct xdp_md *ctx)
{
    bpf_printk("[hook_route_xdp] Called...");

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    long rc;

    // invalid pkt: ethhdr overflow
    if (data + sizeof(struct ethhdr) > data_end)
    {
        bpf_printk("[hook_route_xdp] drop 1");
        return XDP_DROP;
    }

    // ptr to l3 protocol headers (or inner l2, if vlan)
    void *l3hdr = data + sizeof(struct ethhdr);

    // ethertype
    __u16 ether_proto = bpf_ntohs(eth->h_proto);

    struct bpf_fib_lookup fib_params = {};

    // vlan header found
    if (ether_proto == ETH_P_8021Q || ether_proto == ETH_P_8021AD)
    {
        // tagged pkt on non-trunked port, drop
        struct vlan_hdr *vhdr = l3hdr;
        if (l3hdr + sizeof(struct vlan_hdr) > data_end)
        {
            bpf_printk("[hook_route_xdp] drop 2");
            return XDP_DROP;
        }

        l3hdr += sizeof(struct vlan_hdr);
        ether_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (ether_proto == ETH_P_IP)
    {
        if (l3hdr + sizeof(struct iphdr) > data_end)
        {
            bpf_printk("[hook_route_xdp] drop 3");
            return XDP_DROP;
        }
        struct iphdr *ip = l3hdr;

        if (ip->ttl <= 1)
        {
            // return XDP_PASS;
            bpf_printk("[hook_route_xdp] drop 4");
            return XDP_DROP;
        }

        fib_params.family = AF_INET;
        fib_params.tos = ip->tos;
        fib_params.l4_protocol = ip->protocol;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(ip->tot_len);
        fib_params.ipv4_src = ip->saddr;
        fib_params.ipv4_dst = ip->daddr;

        // goto forward;
    }
    else if (ether_proto == ETH_P_IPV6)
    {
        if (l3hdr + sizeof(struct ipv6hdr) > data_end)
        {
            bpf_printk("[hook_route_xdp] drop 5");
            return XDP_DROP;
        }
        struct ipv6hdr *ip6 = l3hdr;

        if (ip6->hop_limit <= 1)
        {
            // return XDP_PASS;
            bpf_printk("[hook_route_xdp] drop 6");
            return XDP_DROP;
        }
        fib_params.family = AF_INET6;
        fib_params.flowinfo = *(__be32 *)ip6 & bpf_htonl(0x0FFFFFFF);
        fib_params.l4_protocol = ip6->nexthdr;
        fib_params.sport = 0;
        fib_params.dport = 0;
        fib_params.tot_len = bpf_ntohs(ip6->payload_len);
        *(struct in6_addr *)fib_params.ipv6_src = ip6->saddr;
        *(struct in6_addr *)fib_params.ipv6_dst = ip6->daddr;

        // goto forward;
    }
    else
    {
        bpf_printk("[hook_route_xdp] drop 7");
        return XDP_DROP;
    }

    // forward:
    fib_params.ifindex = ctx->ingress_ifindex;

    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    switch (rc)
    {
    case BPF_FIB_LKUP_RET_SUCCESS:
        _decr_ttl(ether_proto, l3hdr);
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        bpf_printk("[hook_route_xdp] redirect -> idx#%d", fib_params.ifindex);
        return bpf_redirect(fib_params.ifindex, 0);
    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        bpf_printk("[hook_route_xdp] drop 8");
        return XDP_DROP;
    case BPF_FIB_LKUP_RET_NOT_FWDED:
    case BPF_FIB_LKUP_RET_FWD_DISABLED:
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    case BPF_FIB_LKUP_RET_NO_NEIGH:
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:
        // return XDP_PASS;
        bpf_printk("[hook_route_xdp] drop 9");
        return XDP_DROP;
    }

    // return XDP_PASS;
    bpf_printk("[hook_route_xdp] drop 10");
    return XDP_DROP;
}

SEC("xdp/hook_drop_xdp")
int hook_drop_xdp(struct xdp_md *ctx)
{
    bpf_printk("[hook_drop_xdp] Called... Dropping");
    return XDP_DROP;
}

SEC("xdp/hook_egress_xdp")
int hook_egress_xdp(struct xdp_md *ctx)
{
    bpf_printk("[hook_egress_xdp] Called... Dropping");
    return XDP_DROP;
}

SEC("xdp/Prog_xdp")
int Prog_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;

    struct traffic_key t_key = {0};

    struct traffic_stats traffic_stat = {0};
    traffic_stat.timestamp = bpf_ktime_get_boot_ns();
    traffic_stat.size = data_end - data;

    struct ethhdr *eth_header = data;
    __u16 nh_off = sizeof(*eth_header);

    if (data + nh_off > data_end)
    {
        bpf_printk("[XDP] Dropping malformed (short) packet 1");
        if (PORT_CFG.hook_drop)
        {
            bpf_tail_call(ctx, &Map_jump_table_xdp, HOOK_DROP_XDP);
        }
        goto drop;
    }

    struct fdb_key dst_key = {0};
    dst_key.vlan = PORT_CFG.pvid;

    t_key.proto_l2 = eth_header->h_proto;

    struct vlan_hdr *vlan_header = NULL;

    switch (eth_header->h_proto)
    {
    case bpf_htons(ETH_P_8021Q):
        traffic_stat.tagged = 1;
        vlan_header = (void *)eth_header + nh_off;
        nh_off += sizeof(*vlan_header);

        if ((void *)eth_header + nh_off > data_end)
        {
            bpf_printk("[XDP] Dropping malformed (short?) packet 2");
            if (PORT_CFG.hook_drop)
            {
                bpf_tail_call(ctx, &Map_jump_table_xdp, HOOK_DROP_XDP);
            }
            goto drop;
        }

        t_key.proto_l2 = vlan_header->h_vlan_encapsulated_proto;

        dst_key.vlan = bpf_ntohs(vlan_header->h_vlan_TCI) & VLAN_VID_MASK;

        if (dst_key.vlan < 1 || dst_key.vlan > 4094)
        {
            bpf_printk("[XDP] Dropping malformed packet VLAN out of range (1-4094): VLAN#%d", dst_key.vlan);
            if (PORT_CFG.hook_drop)
            {
                bpf_tail_call(ctx, &Map_jump_table_xdp, HOOK_DROP_XDP);
            }
            goto drop;
        }

        if (PORT_CFG.ingress_filtering == 1)
        {
            _Bool accept = 0;
            if (dst_key.vlan == PORT_CFG.pvid)
            {
                accept = 1;
            }
            else
            {
                __u8 section = dst_key.vlan / 64;
                __u64 offset_bitmask = 1 << (dst_key.vlan % 64);
                if (PORT_CFG.vlan_bitmask[section] & offset_bitmask)
                {
                    accept = 1;
                }
            }
            if (accept == 0)
            {
                if (PORT_CFG.hook_drop)
                {
                    bpf_tail_call(ctx, &Map_jump_table_xdp, HOOK_DROP_XDP);
                }
                goto drop;
            }
        }
        break;
    case bpf_htons(ETH_P_8021AD):
        // todo - handle 802.1ad
        bpf_printk("[XDP] !!! TODO - DROPPING QinQ 802.1ad VLAN PACKET!");

        traffic_stat.tagged = 1;
        vlan_header = (void *)eth_header + nh_off;
        nh_off += sizeof(*vlan_header);

        if ((void *)eth_header + nh_off > data_end)
        {
            bpf_printk("[XDP] Dropping malformed (short?) packet 3");
            if (PORT_CFG.hook_drop)
            {
                bpf_tail_call(ctx, &Map_jump_table_xdp, HOOK_DROP_XDP);
            }
            goto drop;
        }

        t_key.proto_l2 = vlan_header->h_vlan_encapsulated_proto;

        if (PORT_CFG.hook_drop)
        {
            bpf_tail_call(ctx, &Map_jump_table_xdp, HOOK_DROP_XDP);
        }
        goto drop;
        break;
    }
    t_key.vlan = dst_key.vlan;

    if (data + nh_off + sizeof(struct iphdr) > data_end)
    {
        bpf_printk("[XDP] DROPPING SHORT NON-IP PACKET?");
        goto drop;
    }
    struct iphdr *ip_header = data + nh_off;
    __u16 size = bpf_ntohs(ip_header->tot_len);

    t_key.src_ipv4 = ip_header->saddr;
    t_key.dst_ipv4 = ip_header->daddr;
    t_key.proto_l3 = ip_header->protocol;
    traffic_stat.size = ip_header->tot_len;

    struct fdb_key src_key = {0};
    src_key.mac = toUnsigned64(eth_header->h_source);

    src_key.vlan = dst_key.vlan; // todo change vlan here?

    struct fdb_val val_src = {.iface_index = PORT_CFG.if_index, .tagged = traffic_stat.tagged};
    val_src.ktimestamp = traffic_stat.timestamp;

    bpf_map_update_elem(&Map_fdb_xdp, &src_key, &val_src, BPF_ANY);

    dst_key.mac = toUnsigned64(eth_header->h_dest);

    if (eth_header->h_dest[0] == 0xff)
    {
        goto pass;
    }

    __u64 self_mac64 = toUnsigned64(PORT_CFG.mac);
    if (dst_key.mac == self_mac64)
    {
        bpf_printk("[XDP] BYTES MATCH SELF MAC");
    }

    struct fdb_val *entry = bpf_map_lookup_elem(&Map_fdb_xdp, &dst_key);
    if (!entry)
    {
        goto pass;
    }
    else if (val_src.ktimestamp > entry->ktimestamp + FDB_MAX_AGE_NS)
    {
        bpf_map_delete_elem(&Map_fdb_xdp, &dst_key);
        bpf_printk("[RETURN_XDP_PASS] fdb entry expired, broadcasting... val_src.ts: %llu, entry->ts: %llu", val_src.ktimestamp, entry->ktimestamp);
        goto pass;
    }
    else if (entry->tagged && !traffic_stat.tagged)
    {
        vlan_tag_push(ctx, data, dst_key.vlan);
    }
    else if (!entry->tagged && traffic_stat.tagged)
    {
        char *dest = data;
        dest += VLAN_HDR_SZ;

        if (dest + (ETH_ALEN * 2) > data_end)
        {
            bpf_printk("Dropping malformed (Short) packet 3");
            if (PORT_CFG.hook_drop)
            {
                bpf_tail_call(ctx, &Map_jump_table_xdp, HOOK_DROP_XDP);
            }
            goto drop;
        }

        /*
         * Notice: Taking over vlan_hdr->h_vlan_encapsulated_proto, by
         * only moving two MAC addrs (12 bytes), not overwriting last 2 bytes
         */
        __builtin_memmove(dest, data, ETH_ALEN * 2);
        /* Note: LLVM built-in memmove inlining require size to be constant */

        /* Move start of packet header seen by Linux kernel stack */
        bpf_xdp_adjust_head(ctx, VLAN_HDR_SZ);
    }
    if (PORT_CFG.hook_egress)
    {
        bpf_tail_call(ctx, &Map_jump_table_xdp, HOOK_EGRESS_XDP);
    }
    goto redirect;

redirect:
    if (STATS_ENABLED && t_key.proto_l2 == bpf_htons(ETH_P_IP))
    {
        t_key.target_if_index = entry->iface_index;
        struct traffic_stats *traffic = bpf_map_lookup_elem(&Map_stats_traffic, &t_key);
        if (traffic)
        {
            if (traffic->rx_redirected_packets + 1 < ULLONG_MAX)
            {
                traffic_stat.rx_redirected_packets = traffic->rx_redirected_packets + 1;
            }
            else
            {
                // bpf_printk("[REDIRECT] overflow A");
                traffic_stat.rx_redirected_packets = 1;
            }
            if (traffic->rx_redirected_bytes + size < ULLONG_MAX)
            {
                traffic_stat.rx_redirected_bytes = traffic->rx_redirected_bytes + size;
            }
            else
            {
                // bpf_printk("[REDIRECT] overflow B");
                traffic_stat.rx_redirected_bytes = size - (ULLONG_MAX - traffic->rx_redirected_bytes);
            }
        }
        else
        {
            traffic_stat.rx_redirected_bytes = size;
            traffic_stat.rx_redirected_packets = 1;
        }
        // bpf_printk("[REDIRECT] to: %d, packets: %llu, bytes: %llu", entry->iface_index, traffic_stat.rx_redirected_packets, traffic_stat.rx_redirected_bytes);
        bpf_map_update_elem(&Map_stats_traffic, &t_key, &traffic_stat, BPF_ANY);
    }
    return bpf_redirect(entry->iface_index, 0);

drop:
    if (STATS_ENABLED && t_key.proto_l2 == bpf_htons(ETH_P_IP))
    {
        t_key.target_if_index = PORT_CFG.if_index;
        struct traffic_stats *traffic = bpf_map_lookup_elem(&Map_stats_traffic, &t_key);
        if (traffic)
        {
            if (traffic->rx_dropped_packets + 1 < ULLONG_MAX)
            {
                traffic_stat.rx_dropped_packets = traffic->rx_dropped_packets + 1;
            }
            if (traffic->rx_dropped_bytes + size < ULLONG_MAX)
            {
                traffic_stat.rx_dropped_bytes = traffic->rx_dropped_bytes + size;
            }
        }
        else
        {
            traffic_stat.rx_dropped_bytes = size;
            traffic_stat.rx_dropped_packets = 1;
        }
        bpf_map_update_elem(&Map_stats_traffic, &t_key, &traffic_stat, BPF_ANY);
    }
    return XDP_DROP;

pass:
    if (STATS_ENABLED && t_key.proto_l2 == bpf_htons(ETH_P_IP))
    {
        t_key.target_if_index = PORT_CFG.if_index;
        struct traffic_stats *traffic = bpf_map_lookup_elem(&Map_stats_traffic, &t_key);
        if (traffic)
        {
            if (traffic->rx_passed_packets + 1 < ULLONG_MAX)
            {
                traffic_stat.rx_passed_packets = traffic->rx_passed_packets + 1;
            }
            if (traffic->rx_passed_bytes + size < ULLONG_MAX)
            {
                traffic_stat.rx_passed_bytes = traffic->rx_passed_bytes + size;
            }
        }
        else
        {
            traffic_stat.rx_passed_bytes = size;
            traffic_stat.rx_passed_packets = 1;
        }
        bpf_map_update_elem(&Map_stats_traffic, &t_key, &traffic_stat, BPF_ANY);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";