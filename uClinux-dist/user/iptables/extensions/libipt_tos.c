/* Shared library add-on to iptables to add TOS matching support. */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include <linux/netfilter_ipv4/ipt_tos.h>

/* TOS names and values. */
static
struct TOS_value
{
	unsigned char TOS;
	const char *name;
} TOS_values[] = {
	{ IPTOS_LOWDELAY,    "Minimize-Delay" },
	{ IPTOS_THROUGHPUT,  "Maximize-Throughput" },
	{ IPTOS_RELIABILITY, "Maximize-Reliability" },
	{ IPTOS_MINCOST,     "Minimize-Cost" },
	{ IPTOS_NORMALSVC,   "Normal-Service" },
};

/* Function which prints out usage message. */
static void
help(void)
{
	unsigned int i;

	printf(
"TOS match v%s options:\n"
"[!] --tos value                 Match Type of Service field from one of the\n"
"                                following numeric or descriptive values:\n",
NETFILTER_VERSION);

	for (i = 0; i < sizeof(TOS_values)/sizeof(struct TOS_value);i++)
		printf("                                     %s %u (0x%02x)\n",
		       TOS_values[i].name,
                       TOS_values[i].TOS,
                       TOS_values[i].TOS);
	fputc('\n', stdout);
}

static struct option opts[] = {
	{ "tos", 1, 0, '1' },
	{0}
};

/* Initialize the match. */
static void
init(struct ipt_entry_match *m, unsigned int *nfcache)
{
	*nfcache |= NFC_IP_TOS;
}

static void
parse_tos(const unsigned char *s, struct ipt_tos_info *info)
{
	unsigned int i;
	unsigned int tos;

	if (string_to_number(s, 0, 255, &tos) != -1) {
		if (tos == IPTOS_LOWDELAY
		    || tos == IPTOS_THROUGHPUT
		    || tos == IPTOS_RELIABILITY
		    || tos == IPTOS_MINCOST
		    || tos == IPTOS_NORMALSVC) {
		    	info->tos = (u_int8_t )tos;
		    	return;
		}
	} else {
		for (i = 0; i<sizeof(TOS_values)/sizeof(struct TOS_value); i++)
			if (strcasecmp(s,TOS_values[i].name) == 0) {
				info->tos = TOS_values[i].TOS;
				return;
			}
	}
	exit_error(PARAMETER_PROBLEM, "Bad TOS value `%s'", s);
}

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const struct ipt_entry *entry,
      unsigned int *nfcache,
      struct ipt_entry_match **match)
{
	struct ipt_tos_info *tosinfo = (struct ipt_tos_info *)(*match)->data;

	switch (c) {
	case '1':
		if (check_inverse(optarg, &invert))
			optind++;
		parse_tos(argv[optind-1], tosinfo);
		if (invert)
			tosinfo->invert = 1;
		*flags = 1;
		break;

	default:
		return 0;
	}
	return 1;
}

static void
print_tos(u_int8_t tos, int invert, int numeric)
{
	unsigned int i;

	if (invert)
		fputc('!', stdout);

	if (!numeric) {
		for (i = 0; i<sizeof(TOS_values)/sizeof(struct TOS_value); i++)
			if (TOS_values[i].TOS == tos) {
				printf("%s ", TOS_values[i].name);
				return;
			}
	}
	printf("0x%02x ", tos);
}

/* Final check; must have specified --tos. */
static void
final_check(unsigned int flags)
{
	if (!flags)
		exit_error(PARAMETER_PROBLEM,
			   "TOS match: You must specify `--tos'");
}

/* Prints out the matchinfo. */
static void
print(const struct ipt_ip *ip,
      const struct ipt_entry_match *match,
      int numeric)
{
	printf("TOS match ");
	print_tos(((struct ipt_tos_info *)match->data)->tos,
		  ((struct ipt_tos_info *)match->data)->invert, numeric);
}

/* Saves the union ipt_matchinfo in parsable form to stdout. */
static void
save(const struct ipt_ip *ip, const struct ipt_entry_match *match)
{
	printf("--tos ");
	print_tos(((struct ipt_tos_info *)match->data)->tos,
		  ((struct ipt_tos_info *)match->data)->invert, 0);
}

static
struct iptables_match tos
= { NULL,
    "tos",
    NETFILTER_VERSION,
    IPT_ALIGN(sizeof(struct ipt_tos_info)),
    IPT_ALIGN(sizeof(struct ipt_tos_info)),
    &help,
    &init,
    &parse,
    &final_check,
    &print,
    &save,
    opts
};

void _init(void)
{
	register_match(&tos);
}
