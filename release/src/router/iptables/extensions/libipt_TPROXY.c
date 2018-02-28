/* Shared library add-on to iptables to add TPROXY target support. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_TPROXY.h>

struct tosinfo {
	struct ipt_entry_target t;
	struct ipt_tproxy_target_info tproxy;
};

/* Function which prints out usage message. */
static void
help(void)
{
	printf(
"TPROXY target v%s options:\n"
"  --on-port port                   Redirect connection to port, or the original port if 0\n"
"  --on-ip ip                       Optionally redirect to the given IP\n",
IPTABLES_VERSION);
}

static struct option opts[] = {
	{ "on-port", 1, 0, '1' },
	{ "on-ip", 1, 0, '2' },
	{ 0 }
};

/* Initialize the target. */
static void
init(struct ipt_entry_target *t, unsigned int *nfcache)
{
}

static void
parse_tproxy_lport(const unsigned char *s, struct ipt_tproxy_target_info *info)
{
	int lport;
	
	if (string_to_number(s, 0, 65535, &lport) != -1)
	        info->lport = htons(lport);
	else
	        exit_error(PARAMETER_PROBLEM, "bad --on-proxy `%s'", s);
 
}

static void
parse_tproxy_laddr(const unsigned char *s, struct ipt_tproxy_target_info *info)
{
	struct in_addr *laddr;
	
	if ((laddr = dotted_to_addr(s)) == NULL)
	        exit_error(PARAMETER_PROBLEM, "bad --on-ip `%s'", s);
 	info->laddr = laddr->s_addr;
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      struct ipt_entry_target **target)
{
	struct ipt_tproxy_target_info *tproxyinfo
		= (struct ipt_tproxy_target_info *)(*target)->data;

	switch (c) {
	case '1':
		if (*flags)
			exit_error(PARAMETER_PROBLEM,
			           "TPROXY target: Can't specify --to-port twice");
		parse_tproxy_lport(optarg, tproxyinfo);
		*flags = 1;
		break;
	case '2':
		parse_tproxy_laddr(optarg, tproxyinfo);
		break;

	default:
		return 0;
	}

	return 1;
}

static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
		           "TPROXY target: Parameter --on-port is required");
}

/* Prints out the targinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_target *target,
      int numeric)
{
	const struct ipt_tproxy_target_info *tproxyinfo =
		(const struct ipt_tproxy_target_info *)target->data;
	printf("TPROXY redirect %s:%d", addr_to_dotted((struct in_addr *) &tproxyinfo->laddr), ntohs(tproxyinfo->lport));
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_target *target)
{
	const struct ipt_tproxy_target_info *tproxyinfo =
		(const struct ipt_tproxy_target_info *)target->data;

	printf("--on-port %d ", ntohs(tproxyinfo->lport));
	printf("--on-ip %s ", addr_to_dotted((struct in_addr *) &tproxyinfo->laddr));
}

static struct iptables_target tproxy = {
    .name          = "TPROXY",
    .version       = IPTABLES_VERSION,
    .size          = IPT_ALIGN(sizeof(struct ipt_tproxy_target_info)),
    .userspacesize = IPT_ALIGN(sizeof(struct ipt_tproxy_target_info)),
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
	register_target(&tproxy);
}
