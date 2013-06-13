/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code has been sponsored by Sophos Astaro <http://www.sophos.com>
 */

#include "internal.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for memcpy */
#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftables/expr.h>
#include <libnftables/rule.h>
#include "data_reg.h"
#include "expr_ops.h"

struct nft_expr_byteorder {
	enum nft_registers	sreg;
	enum nft_registers	dreg;
	enum nft_byteorder_ops	op;
	unsigned int		len;
	unsigned int		size;
};

static int
nft_rule_expr_byteorder_set(struct nft_rule_expr *e, uint16_t type,
			  const void *data, size_t data_len)
{
	struct nft_expr_byteorder *byteorder =
		(struct nft_expr_byteorder *)e->data;

	switch(type) {
	case NFT_EXPR_BYTEORDER_SREG:
		byteorder->sreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_BYTEORDER_DREG:
		byteorder->dreg = *((uint32_t *)data);
		break;
	case NFT_EXPR_BYTEORDER_OP:
		byteorder->op = *((uint32_t *)data);
		break;
	case NFT_EXPR_BYTEORDER_LEN:
		byteorder->len = *((unsigned int *)data);
		break;
	case NFT_EXPR_BYTEORDER_SIZE:
		byteorder->size = *((unsigned int *)data);
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nft_rule_expr_byteorder_get(struct nft_rule_expr *e, uint16_t type,
			    size_t *data_len)
{
	struct nft_expr_byteorder *byteorder =
		(struct nft_expr_byteorder *)e->data;

	switch(type) {
	case NFT_EXPR_BYTEORDER_SREG:
		if (e->flags & (1 << NFT_EXPR_BYTEORDER_SREG)) {
			*data_len = sizeof(byteorder->sreg);
			return &byteorder->sreg;
		}
		break;
	case NFT_EXPR_BYTEORDER_DREG:
		if (e->flags & (1 << NFT_EXPR_BYTEORDER_DREG)) {
			*data_len = sizeof(byteorder->dreg);
			return &byteorder->dreg;
		}
		break;
	case NFT_EXPR_BYTEORDER_OP:
		if (e->flags & (1 << NFT_EXPR_BYTEORDER_OP)) {
			*data_len = sizeof(byteorder->op);
			return &byteorder->op;
		}
		break;
	case NFT_EXPR_BYTEORDER_LEN:
		if (e->flags & (1 << NFT_EXPR_BYTEORDER_LEN)) {
			*data_len = sizeof(byteorder->len);
			return &byteorder->len;
		}
		break;
	case NFT_EXPR_BYTEORDER_SIZE:
		if (e->flags & (1 << NFT_EXPR_BYTEORDER_SIZE)) {
			*data_len = sizeof(byteorder->size);
			return &byteorder->size;
		}
		break;
	default:
		break;
	}
	return NULL;
}

static int nft_rule_expr_byteorder_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_BYTEORDER_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_BYTEORDER_SREG:
	case NFTA_BYTEORDER_DREG:
	case NFTA_BYTEORDER_OP:
	case NFTA_BYTEORDER_LEN:
	case NFTA_BYTEORDER_SIZE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nft_rule_expr_byteorder_build(struct nlmsghdr *nlh, struct nft_rule_expr *e)
{
	struct nft_expr_byteorder *byteorder =
		(struct nft_expr_byteorder *)e->data;

	if (e->flags & (1 << NFT_EXPR_BYTEORDER_SREG)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_SREG,
				 htonl(byteorder->sreg));
	}
	if (e->flags & (1 << NFT_EXPR_BYTEORDER_DREG)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_DREG,
				 htonl(byteorder->dreg));
	}
	if (e->flags & (1 << NFT_EXPR_BYTEORDER_OP)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_OP,
				 htonl(byteorder->op));
	}
	if (e->flags & (1 << NFT_EXPR_BYTEORDER_LEN)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_LEN,
				 htonl(byteorder->len));
	}
	if (e->flags & (1 << NFT_EXPR_BYTEORDER_SIZE)) {
		mnl_attr_put_u32(nlh, NFTA_BYTEORDER_SIZE,
				 htonl(byteorder->size));
	}
}

static int
nft_rule_expr_byteorder_parse(struct nft_rule_expr *e, struct nlattr *attr)
{
	struct nft_expr_byteorder *byteorder = (struct nft_expr_byteorder *)e->data;
	struct nlattr *tb[NFTA_BYTEORDER_MAX+1] = {};
	int ret = 0;

	if (mnl_attr_parse_nested(attr, nft_rule_expr_byteorder_cb, tb) < 0)
		return -1;

	if (tb[NFTA_BYTEORDER_SREG]) {
		byteorder->sreg =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_SREG]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_SREG);
	}
	if (tb[NFTA_BYTEORDER_DREG]) {
		byteorder->dreg =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_DREG]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_DREG);
	}
	if (tb[NFTA_BYTEORDER_OP]) {
		byteorder->op =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_OP]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_OP);
	}
	if (tb[NFTA_BYTEORDER_LEN]) {
		byteorder->len =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_LEN]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_LEN);
	}
	if (tb[NFTA_BYTEORDER_SIZE]) {
		byteorder->size =
			ntohl(mnl_attr_get_u32(tb[NFTA_BYTEORDER_SIZE]));
		e->flags |= (1 << NFT_EXPR_BYTEORDER_SIZE);
	}

	return ret;
}

static int
nft_rule_expr_byteorder_xml_parse(struct nft_rule_expr *e, char *xml)
{
#ifdef XML_PARSING
	struct nft_expr_byteorder *byteorder = (struct nft_expr_byteorder *)e;
	mxml_node_t *tree = NULL;
	mxml_node_t *node = NULL;
	uint64_t tmp;
	char *endptr = NULL;

	tree = mxmlLoadString(NULL, xml, MXML_OPAQUE_CALLBACK);
	if (tree == NULL)
		return -1;

	if (mxmlElementGetAttr(tree, "type") == NULL)
		goto err;

	if (strcmp("byteorder", mxmlElementGetAttr(tree, "type")) != 0)
		goto err;

	node = mxmlFindElement(tree, tree, "sreg", NULL, NULL,
			       MXML_DESCEND_FIRST);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT32_MAX || tmp < 0 || *endptr)
		goto err;

	byteorder->sreg = tmp;
	e->flags |= (1 << NFT_EXPR_BYTEORDER_SREG);

	node = mxmlFindElement(tree, tree, "dreg", NULL, NULL, MXML_DESCEND);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT32_MAX || tmp < 0 || *endptr)
		goto err;

	byteorder->dreg = tmp;
	e->flags |= (1 << NFT_EXPR_BYTEORDER_DREG);

	node = mxmlFindElement(tree, tree, "op", NULL, NULL, MXML_DESCEND);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT8_MAX || tmp < 0 || *endptr)
		goto err;

	byteorder->op = tmp;
	e->flags |= (1 << NFT_EXPR_BYTEORDER_OP);

	node = mxmlFindElement(tree, tree, "len", NULL, NULL, MXML_DESCEND);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT8_MAX || tmp < 0 || *endptr)
		goto err;

	byteorder->len = tmp;
	e->flags |= (1 << NFT_EXPR_BYTEORDER_LEN);

	node = mxmlFindElement(tree, tree, "size", NULL, NULL, MXML_DESCEND);
	if (node == NULL)
		goto err;

	tmp = strtoull(node->child->value.opaque, &endptr, 10);
	if (tmp > UINT8_MAX || tmp < 0 || *endptr)
		goto err;

	byteorder->size = tmp;
	e->flags |= (1 << NFT_EXPR_BYTEORDER_SIZE);

	mxmlDelete(tree);
	return 0;
err:
	mxmlDelete(tree);
	errno = EINVAL;
	return -1;
#else
	errno = EOPNOTSUPP;
	return -1;
#endif
}

static int
nft_rule_expr_byteorder_snprintf_xml(char *buf, size_t size,
				   struct nft_expr_byteorder *byteorder)
{
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "<sreg>%u</sreg>"
				 "<dreg>%u</dreg>"
				 "<op>%u</op>"
				 "<len>%u</len>"
				 "<size>%u</size>",
		       byteorder->sreg, byteorder->dreg, byteorder->op,
		       byteorder->len, byteorder->size);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_byteorder_snprintf_default(char *buf, size_t size,
				       struct nft_expr_byteorder *byteorder)
{
	int len = size, offset = 0, ret;

	ret = snprintf(buf, len, "sreg=%u dreg=%u op=%u len=%u size=%u ",
		       byteorder->sreg, byteorder->dreg, byteorder->op,
		       byteorder->len, byteorder->size);
	SNPRINTF_BUFFER_SIZE(ret, size, len, offset);

	return offset;
}

static int
nft_rule_expr_byteorder_snprintf(char *buf, size_t size, uint32_t type,
			       uint32_t flags, struct nft_rule_expr *e)
{
	struct nft_expr_byteorder *byteorder = (struct nft_expr_byteorder *)e->data;

	switch(type) {
	case NFT_RULE_O_DEFAULT:
		return nft_rule_expr_byteorder_snprintf_default(buf, size,
								byteorder);
	case NFT_RULE_O_XML:
		return nft_rule_expr_byteorder_snprintf_xml(buf, size,
							    byteorder);
	default:
		break;
	}
	return -1;
}

struct expr_ops expr_ops_byteorder = {
	.name		= "byteorder",
	.alloc_len	= sizeof(struct nft_expr_byteorder),
	.max_attr	= NFTA_BYTEORDER_MAX,
	.set		= nft_rule_expr_byteorder_set,
	.get		= nft_rule_expr_byteorder_get,
	.parse		= nft_rule_expr_byteorder_parse,
	.build		= nft_rule_expr_byteorder_build,
	.snprintf	= nft_rule_expr_byteorder_snprintf,
	.xml_parse	= nft_rule_expr_byteorder_xml_parse,
};