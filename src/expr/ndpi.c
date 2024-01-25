#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/ndpi.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_ndpi {
    NDPI_PROTOCOL_BITMASK proto;
    uint32_t flags;
	char*	hostname;
};

static int nftnl_expr_ndpi_set(struct nftnl_expr *e, uint16_t type,
				 const void *data, uint32_t data_len)
{
	struct nftnl_expr_ndpi *ndpi = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_NDPI_HOSTNAME:
		if (ndpi->hostname)
			xfree(ndpi->hostname);

		ndpi->hostname = strdup(data);
		if (!ndpi->hostname)
			return -1;
		break;
	case NFTNL_EXPR_NDPI_FLAGS:
		memcpy(&ndpi->flags, data, sizeof(ndpi->flags));
		break;
	case NFTNL_EXPR_NDPI_PROTO:
		memcpy(&ndpi->proto, data, sizeof(ndpi->proto));
		break;
	default:
		return -1;
	}
	return 0;
}

static const void *
nftnl_expr_ndpi_get(const struct nftnl_expr *e, uint16_t type,
		      uint32_t *data_len)
{
	struct nftnl_expr_ndpi *ndpi = nftnl_expr_data(e);

	switch(type) {
	case NFTNL_EXPR_NDPI_HOSTNAME:
		*data_len = strlen(ndpi->hostname)+1;
		return ndpi->hostname;
	case NFTNL_EXPR_NDPI_FLAGS:
		*data_len = sizeof(ndpi->flags);
		return &ndpi->flags;
	case NFTNL_EXPR_NDPI_PROTO:
		*data_len = sizeof(ndpi->proto);
		return &ndpi->proto;
	}
	return NULL;
}

static int nftnl_expr_ndpi_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_NDPI_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFTA_NDPI_HOSTNAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			abi_breakage();
		break;
	case NFTA_NDPI_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			abi_breakage();
		break;
	case NFTA_NDPI_PROTO:
		if (mnl_attr_validate(attr, MNL_TYPE_BINARY) < 0)
			abi_breakage();
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static void
nftnl_expr_ndpi_build(struct nlmsghdr *nlh, const struct nftnl_expr *e)
{
	struct nftnl_expr_ndpi *ndpi = nftnl_expr_data(e);

	if (e->flags & (1 << NFTNL_EXPR_NDPI_HOSTNAME))
		mnl_attr_put_strz(nlh, NFTA_NDPI_HOSTNAME, ndpi->hostname);
	if (e->flags & (1 << NFTNL_EXPR_NDPI_FLAGS))
		mnl_attr_put_u32(nlh, NFTA_NDPI_FLAGS, htonl(ndpi->flags));
	if(e->flags & (1 << NFTNL_EXPR_NDPI_PROTO))
		mnl_attr_put(nlh, NFTA_NDPI_PROTO, sizeof(ndpi->proto), &ndpi->proto);
}

static int
nftnl_expr_ndpi_parse(struct nftnl_expr *e, struct nlattr *attr)
{
	struct nftnl_expr_ndpi *ndpi = nftnl_expr_data(e);
	struct nlattr *tb[NFTA_NDPI_MAX+1] = {};

	if (mnl_attr_parse_nested(attr, nftnl_expr_ndpi_cb, tb) < 0)
		return -1;

	if (tb[NFTA_NDPI_HOSTNAME]) {
		if (ndpi->hostname)
			xfree(ndpi->hostname);

		ndpi->hostname = strdup(mnl_attr_get_str(tb[NFTA_NDPI_HOSTNAME]));
		if (!ndpi->hostname)
			return -1;
		e->flags |= (1 << NFTNL_EXPR_NDPI_HOSTNAME);
	}
	if (tb[NFTA_NDPI_FLAGS]) {
		ndpi->flags = ntohl(mnl_attr_get_u32(tb[NFTA_NDPI_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_NDPI_FLAGS);
	}
	if (tb[NFTA_NDPI_PROTO]) {
		memcpy(&ndpi->proto,
			mnl_attr_get_payload(tb[NFTA_NDPI_PROTO]),
			mnl_attr_get_payload_len(tb[NFTA_NDPI_PROTO])
		);
		e->flags |= (1 << NFTNL_EXPR_NDPI_PROTO);
	}

	return 0;
}


static int
nftnl_expr_ndpi_snprintf(char *buf, size_t remain,
			uint32_t flags, const struct nftnl_expr *e)
{
	struct nftnl_expr_ndpi *ndpi = nftnl_expr_data(e);
	int ret, offset = 0;

	char *prot_short_str[NDPI_NUM_BITS] = { /*NDPI_PROTOCOL_SHORT_STRING,*/ NULL, };
	char  prot_disabled[NDPI_NUM_BITS+1] = { 0, };

	nft_ndpi_get_protos(prot_short_str, prot_disabled);

	if (e->flags & (1 << NFTNL_EXPR_NDPI_HOSTNAME)) {
		ret = snprintf(buf, remain, "host %s ", ndpi->hostname);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	}

	if ((e->flags & (1 << NFTNL_EXPR_NDPI_FLAGS))) {
        const char *cinv = (ndpi->flags & NFT_NDPI_FLAG_INVERT) ? "!":"";
        int i,c,l,t;
		if (ndpi->flags & NFT_NDPI_FLAG_ERROR) {
			ret = snprintf(buf + offset, remain, "%sndpi error ",cinv);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
            return offset;
		}
		if (ndpi->flags & NFT_NDPI_FLAG_INPROGRESS) {
			ret = snprintf(buf + offset, remain, "%sndpi inprogress ",cinv);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
            for (l = i = 0; i < NDPI_NUM_BITS; i++) {
                if (prot_short_str[i] && !prot_disabled[i] && NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi->proto, i) != 0){
                    ret = snprintf(buf + offset, remain, "%s%s", l++ ? "," : "", prot_short_str[i]);
					SNPRINTF_BUFFER_SIZE(ret, remain, offset);
				}
            }
            if(l == 0) {
                ret = snprintf(buf + offset, remain, "no protos ");
				SNPRINTF_BUFFER_SIZE(ret, remain, offset);
            }

            return offset;
		}
		if (ndpi->flags & NFT_NDPI_FLAG_UNTRACKED) {
			ret = snprintf(buf + offset, remain,  "%sndpi untracked ",cinv);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
            return offset;
		}
		if (ndpi->flags & NFT_NDPI_FLAG_HAVE_MASTER) {
			ret = snprintf(buf + offset, remain, "%sndpi have-master ",cinv);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
            return offset;
		}

        for (t = c = i = 0; i < NDPI_NUM_BITS; i++) {
		    if (!prot_short_str[i] || prot_disabled[i] || !strncmp(prot_short_str[i], "badproto_", 9)) continue;
		    t++;
		    if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi->proto, i) != 0) c++;
        }
        ret = snprintf(buf + offset, remain, "%sndpi ", cinv);
		SNPRINTF_BUFFER_SIZE(ret, remain, offset);

		if ((ndpi->flags & NFT_NDPI_FLAG_M_PROTO) && !(ndpi->flags & NFT_NDPI_FLAG_P_PROTO)) {
			ret = snprintf(buf + offset, remain, "match-master ");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}
        if (!(ndpi->flags & NFT_NDPI_FLAG_M_PROTO) && (ndpi->flags & NFT_NDPI_FLAG_P_PROTO)) {
			ret = snprintf(buf + offset, remain, "match-proto ");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}
        if(!c){
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
			return offset;
		}

		if( c == t-1 &&
			!NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi->proto, NDPI_PROTOCOL_UNKNOWN) )
		{
			ret = snprintf(buf + offset, remain, " all protocols");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
			return offset;
		}

        if (ndpi->flags & NFT_NDPI_FLAG_JA3S) {
			ret = snprintf(buf + offset, remain, " %sja3s ",cinv);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}else if (ndpi->flags & NFT_NDPI_FLAG_JA3C) {
        	ret = snprintf(buf + offset, remain, " %sja3c ",cinv);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
        }else if (ndpi->flags & NFT_NDPI_FLAG_TLSFP) {
            ret = snprintf(buf + offset, remain, " %stlsfp ",cinv);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
        }else if (ndpi->flags & NFT_NDPI_FLAG_TLSV) {
            ret = snprintf(buf + offset, remain, " %stlsv ",cinv);
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
        }else{
            ret = snprintf(buf + offset, remain, " protocol%s ", c > 1 ? "s" : "");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
        }
        if(c > t/2 + 1) {
	        ret = snprintf(buf + offset, remain, "all");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
	        for (i = 1; i < NDPI_NUM_BITS; i++) {
                if (prot_short_str[i] && !prot_disabled[i] && NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi->proto, i) == 0){
					ret = snprintf(buf + offset, remain, ",-%s", prot_short_str[i]);
					SNPRINTF_BUFFER_SIZE(ret, remain, offset);
				}
	        }
	        return offset;
	    }

        for (l = i = 0; i < NDPI_NUM_BITS; i++) {
            if (prot_short_str[i] && !prot_disabled[i] && NDPI_COMPARE_PROTOCOL_TO_BITMASK(ndpi->proto, i) != 0){
				ret = snprintf(buf + offset, remain, "%s%s", l++ ? "," : "", prot_short_str[i]);
				SNPRINTF_BUFFER_SIZE(ret, remain, offset);
			}
        }
	}

	return offset;
}

static void nftnl_expr_ndpi_free(const struct nftnl_expr *e)
{
	struct nftnl_expr_ndpi *ndpi = nftnl_expr_data(e);

	xfree(ndpi->hostname);
}

struct expr_ops expr_ops_ndpi = {
	.name		= "ndpi",
	.alloc_len	= sizeof(struct nftnl_expr_ndpi),
	.max_attr	= NFTA_NDPI_MAX,
	.free		= nftnl_expr_ndpi_free,
	.set		= nftnl_expr_ndpi_set,
	.get		= nftnl_expr_ndpi_get,
	.parse		= nftnl_expr_ndpi_parse,
	.build		= nftnl_expr_ndpi_build,
	.output		= nftnl_expr_ndpi_snprintf,
};
