#include <stdio.h>
#include <getopt.h>
#include <iptables.h>

static void socket_help(void)
{
	printf("socket v%s has no options\n\n", IPTABLES_VERSION);
}

static int socket_parse(int c, char **argv, int invert, unsigned int *flags,
                        const void *entry, struct xt_entry_match **match)
{
	return 0;
}

static void socket_check(unsigned int flags)
{
}

static struct iptables_match socket_reg = {
	.name          = "socket",
	.version       = IPTABLES_VERSION,
	.size          = XT_ALIGN(0),
	.userspacesize = XT_ALIGN(0),
	.parse         = socket_parse,
	.final_check   = socket_check,
	.help          = socket_help,
};

void _init(void)
{
	register_match(&socket_reg);
}
