/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
			  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	//save the position we got passed in with
	struct ethhdr *eth = nh->pos;
	size_t hdrsize = sizeof(struct ethhdr);
	size_t vlan_hdr_size = sizeof(struct vlan_hdr);
	struct vlan_hdr *vl_hdr;
	__u16 h_proto;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	//move cursor past ether header
	nh->pos += hdrsize;

	//populate pointer to eth header for anyone outside the function
	*ethhdr = eth;
	//save the cursor to the vlh struct
	vl_hdr = nh->pos;

	h_proto = eth->h_proto;


	
	if (proto_is_vlan(eth->h_proto)){
		// skip past the vlans, but check the verifier
		if((vl_hdr + vlan_hdr_size) < data_end){
			h_proto = vl_hdr->h_vlan_encapsulated_proto;
		}
		vl_hdr++;
	}

	//we have moved past a vlan header, update the cursor
	// if not, then this is basically a no-op
	nh->pos = vl_hdr;
	return h_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ipv6 = nh->pos;

	if(ipv6 + 1 > data_end)
		return -1;

	nh->pos = ipv6 + 1;
	*ip6hdr = ipv6;

	return ipv6->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	// save the current cursor position to the icmpv6hdr struct
	struct icmp6hdr *icmp6 = nh->pos;

	if(icmp6 + 1 > data_end)
		return -1;

	// advance the cursor
	nh->pos = icmp6 + 1;
	//set the passed in struct to point to the correct spot
	//so that we can use the struct offset to create useful data
	*icmp6hdr = icmp6;

	return bpf_ntohs(icmp6->icmp6_sequence);
}

/* Assignment 4: Parse past the vlan headers */
//static __always_inline int parse_vlan(struct hdr_cursor *nh,
//		void *data_end, struct vlan_hdr **v_hdr)
//{
//	// save off the position of the cursor
//	struct vlan_hdr *vlan = nh->pos;
//	//pointer math if the structure is past the end of the packet
//	if(vlan + 1 > data_end)
//		return -1;
//
//	//advance the cursor pointer past the vlan header
//	nh->pos = vlan + 1;
//	*v_hdr = vlan;
//	return bpf_ntohs(vlan->h_vlan_TCI);
//}


SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr * ip6;
	struct icmp6hdr * icmpv6;
	//struct vlan_hdr * vlan_head;
	//const char ip6h_msg[] = "nh_type:%d\n";
	//const char ip6h1_msg[] = "bpf_htons(0x3A)=%d\n";
	//const char icmp_seq_msg[] = "seq_num:%d\n";

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	int seq_num;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)){
		nh_type = parse_ip6hdr(&nh, data_end, &ip6); 
		if(nh_type == 58 ){
			seq_num = parse_icmp6hdr(&nh, data_end, &icmpv6);
			if((seq_num % 2) == 0){
				action = XDP_DROP;
				goto out;
			}
		}
	}
	if (nh_type == bpf_htons(ETH_P_IP)){
		goto out;
	}

	
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
