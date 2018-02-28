/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (c) 2007 BalaBit IT Ltd.
 * Author: Krisztian Kovacs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tproxy.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#if 1
#define DEBUGP printk
#else
#define DEBUGP(f, args...)
#endif

static int
match(const struct sk_buff *skb,
      const struct net_device *in,
      const struct net_device *out,
      const struct xt_match *match,
      const void *matchinfo,
      int offset,
      unsigned int protoff,
      int *hotdrop)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct udphdr _hdr, *hp;
	struct sock *sk;

	/* TCP/UDP only */
	if ((iph->protocol != IPPROTO_TCP) &&
	    (iph->protocol != IPPROTO_UDP))
		return 0;

	hp = skb_header_pointer(skb, iph->ihl * 4, sizeof(_hdr), &_hdr);
	if (hp == NULL)
		return 0;

	sk = ip_tproxy_get_sock(iph->protocol,
				iph->saddr, iph->daddr,
				hp->source, hp->dest, in);
	if (sk != NULL) {
		if ((iph->protocol == IPPROTO_TCP) && (sk->sk_state == TCP_TIME_WAIT))
			inet_twsk_put(inet_twsk(sk));
		else
			sock_put(sk);
	}

	DEBUGP(KERN_DEBUG "socket match: proto %d %08x:%d -> %08x:%d sock %p\n",
	       iph->protocol, ntohl(iph->saddr), ntohs(hp->source),
	       ntohl(iph->daddr), ntohs(hp->dest), sk);

	return (sk != NULL);
}

static struct xt_match socket_matches[] = {
	{
		.name		= "socket",
		.match		= match,
		.matchsize	= 0,
		.family		= AF_INET,
		.me		= THIS_MODULE,
	},
};

static int __init ipt_socket_init(void)
{
	return xt_register_matches(socket_matches, ARRAY_SIZE(socket_matches));
}

static void __exit ipt_socket_fini(void)
{
	xt_unregister_matches(socket_matches, ARRAY_SIZE(socket_matches));
}

module_init(ipt_socket_init);
module_exit(ipt_socket_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Krisztian Kovacs <hidden@balabit.hu>");
MODULE_DESCRIPTION("iptables socket match module");
