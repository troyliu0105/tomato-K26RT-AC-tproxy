#ifndef _IP_TPROXY_H
#define _IP_TPROXY_H

#include <linux/types.h>

/* look up and get a reference to a matching socket */
extern struct sock *
ip_tproxy_get_sock(const u8 protocol,
		   const __be32 saddr, const __be32 daddr,
		   const __be16 sport, const __be16 dport,
		   const struct net_device *in);

/* divert skb to a given socket */
extern int
ip_tproxy_do_divert(struct sk_buff *skb,
		    const struct sock *sk);

#endif
