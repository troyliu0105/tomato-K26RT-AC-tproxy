/* Shared library add-on to iptables to add tproxy matching support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <iptables.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ipt_state.h>

/* Function which prints out usage message. */
static void
help(void)
{
}

static struct option opts[] = {
	{0}
};

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	/* Can't cache this */
	*nfcache |= NFC_UNKNOWN;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	return 0;
}

static void 
final_check(unsigned int flags)
{
}

static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
	printf("tproxy ");
}

static void 
save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
}

static struct iptables_match tproxy = {
    .name          = "tproxy",
    .version       = IPTABLES_VERSION,
    .size          = 0, 
    .userspacesize = 0, 
    .help          = help,
    .init          = init,
    .parse         = parse,
    .final_check   = final_check,
    .print         = print,
    .save          = save,
    .extra_opts    = opts,
};

void _init(void)
{
	register_match(&tproxy);
}
