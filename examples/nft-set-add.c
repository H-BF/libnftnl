/*
 * (C) 2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stddef.h>	/* for offsetof */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/set.h>

static struct nft_set *setup_set(uint8_t family, const char *table,
				 const char *name)
{
	struct nft_set *s = NULL;

	s = nft_set_alloc();
	if (s == NULL) {
		perror("OOM");
		exit(EXIT_FAILURE);
	}

	nft_set_attr_set_str(s, NFT_SET_ATTR_TABLE, table);
	nft_set_attr_set_str(s, NFT_SET_ATTR_NAME, name);
	nft_set_attr_set_u32(s, NFT_SET_ATTR_FAMILY, family);
	nft_set_attr_set_u32(s, NFT_SET_ATTR_KEY_LEN, 2);
	nft_set_attr_set_u32(s, NFT_SET_ATTR_ID, 1);
	nft_set_attr_set_u32(s, NFT_SET_ATTR_FLAGS, NFT_SET_CONSTANT);

	return s;
}

static void nft_mnl_batch_put(char *buf, uint16_t type, uint32_t seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = NFNL_SUBSYS_NFTABLES;
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	struct nft_set *s;
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *batch;
	uint8_t family;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t seq = time(NULL);
	int ret;

	if (argc != 4) {
		fprintf(stderr, "Usage: %s <family> <table> <setname>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "ip") == 0)
		family = NFPROTO_IPV4;
	else if (strcmp(argv[1], "ip6") == 0)
		family = NFPROTO_IPV6;
	else if (strcmp(argv[1], "bridge") == 0)
		family = NFPROTO_BRIDGE;
	else if (strcmp(argv[1], "arp") == 0)
		family = NFPROTO_ARP;
	else {
		fprintf(stderr, "Unknown family: ip, ip6, bridge, arp\n");
		exit(EXIT_FAILURE);
	}

	s = setup_set(family, argv[2], argv[3]);

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

	nft_mnl_batch_put(mnl_nlmsg_batch_current(batch),
			  NFNL_MSG_BATCH_BEGIN, seq++);
	mnl_nlmsg_batch_next(batch);

	nlh = nft_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
				      NFT_MSG_NEWSET, family,
				      NLM_F_CREATE|NLM_F_ACK, seq++);

	nft_set_nlmsg_build_payload(nlh, s);
	nft_set_free(s);
	mnl_nlmsg_batch_next(batch);

	nft_mnl_batch_put(mnl_nlmsg_batch_current(batch), NFNL_MSG_BATCH_END,
			 seq++);
	mnl_nlmsg_batch_next(batch);

	ret = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
				mnl_nlmsg_batch_size(batch));
	if (ret == -1) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	mnl_nlmsg_batch_stop(batch);

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	}

	ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_portid(nl), NULL, NULL);
	if (ret < 0) {
		perror("mnl_cb_run");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return EXIT_SUCCESS;
}
