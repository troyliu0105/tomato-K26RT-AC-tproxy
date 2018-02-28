/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (c) 2006-2007 BalaBit IT Ltd.
 * Author: Balazs Scheidler, Krisztian Kovacs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/version.h>
#include <linux/module.h>

#include <linux/net.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#define TPROXY_VALID_HOOKS (1 << NF_IP_PRE_ROUTING)

#if 1
#define DEBUGP printk
#else
#define DEBUGP(f, args...)
#endif

static struct
{
	struct ipt_replace repl;
	struct ipt_standard entries[1];
	struct ipt_error term;
} initial_table __initdata = {
	.repl = {
		.name = "tproxy",
		.valid_hooks = TPROXY_VALID_HOOKS,
		.num_entries = 2,
		.size = sizeof(struct ipt_standard) + sizeof(struct ipt_error),
		.hook_entry = {
			[NF_IP_PRE_ROUTING] = 0 },
		.underflow = {
			[NF_IP_PRE_ROUTING] = 0 },
	},
	.entries = {
		/* PRE_ROUTING */
		{
			.entry = {
				.target_offset = sizeof(struct ipt_entry),
				.next_offset = sizeof(struct ipt_standard),
			},
			.target = {
				.target = {
					.u = {
						.target_size = IPT_ALIGN(sizeof(struct ipt_standard_target)),
					},
				},
				.verdict = -NF_ACCEPT - 1,
			},
		},
	},
	/* ERROR */
	.term = {
		.entry = {
			.target_offset = sizeof(struct ipt_entry),
			.next_offset = sizeof(struct ipt_error),
		},
		.target = {
			.target = {
				.u = {
					.user = {
						.target_size = IPT_ALIGN(sizeof(struct ipt_error_target)),
						.name = IPT_ERROR_TARGET,
					},
				},
			},
			.errorname = "ERROR",
		},
	}
};

static struct ipt_table tproxy_table = {
	.name		= "tproxy",
	.valid_hooks	= TPROXY_VALID_HOOKS,
//	.lock		= RW_LOCK_UNLOCKED,
	.me		= THIS_MODULE,
	.af		= AF_INET,
};

struct sock *
ip_tproxy_get_sock(const u8 protocol,
		   const __be32 saddr, const __be32 daddr,
		   const __be16 sport, const __be16 dport,
		   const struct net_device *in)
{
	struct sock *sk = NULL;

	/* look up socket */
	switch (protocol) {
	case IPPROTO_TCP:
		sk = __inet_lookup(&tcp_hashinfo,
				   saddr, sport, daddr, dport,
				   in->ifindex);
		break;
	case IPPROTO_UDP:
		sk = udp4_lib_lookup(saddr, sport, daddr, dport,
				     in->ifindex);
		break;
	default:
		WARN_ON(1);
	}

	DEBUGP(KERN_DEBUG "socket lookup: proto %d %08x:%d -> %08x:%d sock %p\n",
	       protocol, ntohl(saddr), ntohs(sport), ntohl(daddr), ntohs(dport), sk);

	return sk;
}
EXPORT_SYMBOL_GPL(ip_tproxy_get_sock);

static unsigned int
ip_tproxy_prerouting(unsigned int hooknum,
		     struct sk_buff **pskb,
		     const struct net_device *in,
		     const struct net_device *out,
		     int (*okfn)(struct sk_buff *))
{
	struct sk_buff *skb = *pskb;
	struct iphdr *ip = ip_hdr(*pskb);

	if (unlikely(in == NULL))
		return NF_ACCEPT;

	/* TCP and UDP only */
	if ((ip->protocol != IPPROTO_TCP) && (ip->protocol != IPPROTO_UDP))
		return NF_ACCEPT;

	/* reassemble fragments */
	if (ip->frag_off & __constant_htons(IP_MF|IP_OFFSET)) {
		skb = ip_defrag(skb, IP_DEFRAG_TP_IN);
		if (skb == NULL)
			return NF_STOLEN;

		ip_send_check(ip);
		*pskb = skb;
	}

	return ipt_do_table(pskb, hooknum, in, out, &tproxy_table);
}

static struct nf_hook_ops ip_tproxy_pre_ops = {
	.hook		= ip_tproxy_prerouting,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum	= NF_IP_PRE_ROUTING,
	.priority	= NF_IP_PRI_TPROXY
};

static int __init init(void)
{
	int ret;

	ret = ipt_register_table(&tproxy_table, &initial_table.repl);
	if (ret < 0) {
		printk("IP_TPROXY: can't register tproxy table.\n");
		return ret;
	}

	ret = nf_register_hook(&ip_tproxy_pre_ops);
	if (ret < 0) {
		printk("IP_TPROXY: can't register prerouting hook.\n");
		goto clean_table;
	}

	printk("IP_TPROXY: Transparent proxy support initialized, version 4.0.0\n"
	       "IP_TPROXY: Copyright (c) 2006-2007 BalaBit IT Ltd.\n");

	return ret;

 clean_table:
	ipt_unregister_table(&tproxy_table);
	return ret;
}

static void __exit fini(void)
{
	nf_unregister_hook(&ip_tproxy_pre_ops);
	ipt_unregister_table(&tproxy_table);
}

module_init(init);
module_exit(fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krisztian Kovacs <hidden@balabit.hu>");
MODULE_DESCRIPTION("iptables transparent proxy table");
