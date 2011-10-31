#include "gradm.h"

struct family_set sock_families[] = {
	{ "unix", AF_UNIX },
	{ "local", AF_LOCAL },
	{ "inet", AF_INET },
	{ "ipv4", AF_INET },
	{ "ax25", AF_AX25 },
	{ "ipx", AF_IPX },
	{ "appletalk", AF_APPLETALK },
	{ "netrom", AF_NETROM },
	{ "bridge", AF_BRIDGE },
	{ "atmpvc", AF_ATMPVC },
	{ "x25", AF_X25 },
	{ "ipv6", AF_INET6 },
	{ "inet6", AF_INET6 },
	{ "rose", AF_ROSE },
	{ "decnet", AF_DECnet },
	{ "netbeui", AF_NETBEUI },
	{ "security", AF_SECURITY },
	{ "key", AF_KEY },
	{ "netlink", AF_NETLINK },
	{ "route", AF_ROUTE },
	{ "packet", AF_PACKET },
	{ "ash", AF_ASH },
	{ "econet", AF_ECONET },
	{ "atmsvc", AF_ATMSVC },
	{ "rds", AF_RDS },
	{ "sna", AF_SNA },
	{ "irda", AF_IRDA },
	{ "ppox", AF_PPOX },
	{ "wanpipe", AF_WANPIPE },
	{ "llc", AF_LLC },
	{ "tipc", AF_TIPC },
	{ "bluetooth", AF_BLUETOOTH },
	{ "iucv", AF_IUCV },
	{ "rxrpc", AF_RXRPC },
	{ "isdn", AF_ISDN },
	{ "phonet", AF_PHONET },
	{ "ieee802154", AF_IEEE802154 },
	{ "caif", AF_CAIF },
	{ "all", -1 }
};

void
add_sock_family(struct proc_acl *subject, char *family)
{
	int i;

	if (!strcmp(family, "all")) {
		for (i = 0; i < SIZE(subject->sock_families); i++) {
			subject->sock_families[i] = -1;
		}
		return;
	}

	for (i = 0; i < SIZE(sock_families); i++) {
		if (strcmp(sock_families[i].family_name, family))
			continue;
		else
			break;
	}

	if (i == SIZE(sock_families)) {
		fprintf(stderr, "Invalid socket family %s on line %lu of %s.\n",
			family, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	subject->sock_families[sock_families[i].family_val / 32] |=
				(1 << (sock_families[i].family_val % 32));

	return;
}

void
add_role_allowed_host(struct role_acl *role, char *host, u_int32_t netmask)
{
	struct hostent *he;
	char **p;

	he = gethostbyname(host);
	if (he == NULL) {
		fprintf(stderr, "Error resolving hostname %s, on line %lu of %s\n", host, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}
	if (he->h_addrtype != AF_INET) {
		fprintf(stderr, "Hostname %s on line %lu of %s does not resolve to an IPv4 address.\n", host, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}
	p = he->h_addr_list;
	while (*p) {
		add_role_allowed_ip(role, (u_int32_t)**p, netmask);
		p++;
	}

	return;
}

void
add_role_allowed_ip(struct role_acl *role, u_int32_t addr, u_int32_t netmask)
{
	struct role_allowed_ip **roleipp;
	struct role_allowed_ip *roleip;

	num_pointers++;

	roleip =
	    (struct role_allowed_ip *) calloc(1,
					      sizeof (struct role_allowed_ip));
	if (!roleip)
		failure("calloc");

	roleipp = &(role->allowed_ips);

	if (*roleipp)
		(*roleipp)->next = roleip;

	roleip->prev = *roleipp;

	roleip->addr = addr;
	roleip->netmask = netmask;

	*roleipp = roleip;

	return;
}

void add_host_acl(struct proc_acl *subject, u_int8_t mode, char *host, struct ip_acl *acl_tmp)
{
	struct hostent *he;
	char **p;

	he = gethostbyname(host);
	if (he == NULL) {
		fprintf(stderr, "Error resolving hostname %s, on line %lu of %s\n", host, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}
	if (he->h_addrtype != AF_INET) {
		fprintf(stderr, "Hostname %s on line %lu of %s does not resolve to an IPv4 address.\n", host, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}
	p = he->h_addr_list;
	while (*p) {
		memcpy(&(acl_tmp->addr), *p, sizeof(acl_tmp->addr));
		add_ip_acl(subject, mode, acl_tmp);
		p++;
	}

	return;
}

void
add_ip_acl(struct proc_acl *subject, u_int8_t mode, struct ip_acl *acl_tmp)
{
	struct ip_acl *p;
	int i;

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.\n  Definition "
			"of an IP policy without a subject definition.\n"
			"The RBAC system will not be allowed to be "
			"enabled until this problem is fixed.\n",
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	/* add one for the pointer to array of pointers */
	if (subject->ips == NULL)
		num_pointers++;

	num_pointers++;

	subject->ip_num++;
	if (subject->ips == NULL)
		subject->ips = gr_dyn_alloc(subject->ip_num * sizeof(struct ip_acl *));
	else
		subject->ips = gr_dyn_realloc(subject->ips, subject->ip_num * sizeof(struct ip_acl *));

	p = (struct ip_acl *) calloc(1, sizeof (struct ip_acl));
	if (!p)
		failure("calloc");

	*(subject->ips + subject->ip_num - 1) = p;

	p->mode = mode;
	if (acl_tmp->iface != NULL)
		num_pointers++;
	p->iface = acl_tmp->iface;
	p->addr = acl_tmp->addr;
	p->netmask = acl_tmp->netmask;
	p->low = acl_tmp->low;
	p->high = acl_tmp->high;
	memcpy(p->proto, acl_tmp->proto, sizeof (acl_tmp->proto));
	p->type = acl_tmp->type;

	for (i = 0; i < 8; i++)
		subject->ip_proto[i] |= p->proto[i];
	subject->ip_type |= p->type;

	return;
}

u_int32_t
get_ip(char *ip)
{
	struct in_addr address;

	if (!inet_aton(ip, &address)) {
		fprintf(stderr, "Invalid IP on line %lu of %s.\n", lineno,
			current_acl_file);
		exit(EXIT_FAILURE);
	}

	return address.s_addr;
}

void
conv_name_to_type(struct ip_acl *ip, char *name)
{
	struct protoent *proto;
	unsigned short i;

	if (!strcmp(name, "raw_proto"))
		ip->proto[IPPROTO_RAW / 32] |= (1 << (IPPROTO_RAW % 32));
	else if (!strcmp(name, "raw_sock"))
		ip->type |= (1 << SOCK_RAW);
	else if (!strcmp(name, "any_sock")) {
		ip->type = ~0;
		ip->type &= ~(1 << 0);	// there is no sock type 0
	} else if (!strcmp(name, "any_proto")) {
		for (i = 0; i < 8; i++)
			ip->proto[i] = ~0;
	} else if (!strcmp(name, "stream"))
		ip->type |= (1 << SOCK_STREAM);
	else if (!strcmp(name, "dgram"))
		ip->type |= (1 << SOCK_DGRAM);
	else if (!strcmp(name, "rdm"))
		ip->type |= (1 << SOCK_RDM);
	else if (!strcmp(name, "tcp")) {	// silly protocol 0
		ip->proto[IPPROTO_IP / 32] |= (1 << (IPPROTO_IP % 32));
		ip->proto[IPPROTO_TCP / 32] |= (1 << (IPPROTO_TCP % 32));
	} else if (!strcmp(name, "udp")) {	// silly protocol 0
		ip->proto[IPPROTO_IP / 32] |= (1 << (IPPROTO_IP % 32));
		ip->proto[IPPROTO_UDP / 32] |= (1 << (IPPROTO_UDP % 32));
	} else if ((proto = getprotobyname(name)))
		ip->proto[proto->p_proto / 32] |= (1 << (proto->p_proto % 32));
	else {
		fprintf(stderr, "Invalid type/protocol: %s\n", name);
		exit(EXIT_FAILURE);
	}
	return;
}
