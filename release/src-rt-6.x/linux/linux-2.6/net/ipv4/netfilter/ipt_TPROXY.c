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

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/inet_sock.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ip_tproxy.h>
#include <linux/netfilter_ipv4/ipt_TPROXY.h>

#if 1
#define DEBUGP printk
#else
#define DEBUGP(f, args...)
#endif

static unsigned int
target(struct sk_buff **pskb,
       const struct net_device *in,
       const struct net_device *out,
       unsigned int hooknum,
       const struct xt_target *target,
       const void *targinfo)
{
	const struct iphdr *iph = ip_hdr(*pskb);
	const struct ipt_tproxy_target_info *tgi =
		(const struct ipt_tproxy_target_info *) targinfo;
	struct sk_buff *skb = *pskb;
	struct udphdr _hdr, *hp;

	/* TCP/UDP only */
	if ((iph->protocol != IPPROTO_TCP) &&
	    (iph->protocol != IPPROTO_UDP))
		return NF_ACCEPT;

	hp = skb_header_pointer(*pskb, iph->ihl * 4, sizeof(_hdr), &_hdr);
	if (hp == NULL)
		return NF_DROP;

	skb->nf_tproxy.redirect_address = tgi->laddr ? : iph->daddr;
	skb->nf_tproxy.redirect_port = tgi->lport ? : hp->dest;

	DEBUGP(KERN_DEBUG "redirecting: proto %d %08x:%d -> %08x:%d\n",
	       iph->protocol, ntohl(iph->daddr), ntohs(hp->dest),
	       ntohl(skb->nf_tproxy.redirect_address),
	       ntohs(skb->nf_tproxy.redirect_port));

	return NF_ACCEPT;
}

static struct xt_target ipt_tproxy_reg = {
	.name		= "TPROXY",
	.family		= AF_INET,
	.target		= target,
	.targetsize	= sizeof(struct ipt_tproxy_target_info),
	.table		= "tproxy",
	.me		= THIS_MODULE,
};

static int __init init(void)
{
	return xt_register_target(&ipt_tproxy_reg);
}

static void __exit fini(void)
{
	xt_unregister_target(&ipt_tproxy_reg);
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krisztian Kovacs <hidden@balabit.hu>");
MODULE_DESCRIPTION("Netfilter transparent proxy TPROXY target module.");
