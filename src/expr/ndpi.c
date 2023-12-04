#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_ndpi.h>

#include "internal.h"
#include <libmnl/libmnl.h>
#include <libnftnl/expr.h>
#include <libnftnl/rule.h>

struct nftnl_expr_ndpi {
    //NDPI_PROTOCOL_BITMASK flags;
    uint16_t flags;
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
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
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
		mnl_attr_put_u16(nlh, NFTA_NDPI_FLAGS, htonl(ndpi->flags));
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
		ndpi->flags = ntohl(mnl_attr_get_u16(tb[NFTA_NDPI_FLAGS]));
		e->flags |= (1 << NFTNL_EXPR_NDPI_FLAGS);
	}

	return 0;
}

// #define NFT_NDPI_FLAG_INVERT        0x1U
// #define NFT_NDPI_FLAG_ERROR         0x2U
// #define NFT_NDPI_FLAG_M_PROTO       0x4U
// #define NFT_NDPI_FLAG_P_PROTO       0x8U
// #define NFT_NDPI_FLAG_HAVE_MASTER   0x10U
// #define NFT_NDPI_FLAG_HOST          0x20U
// #define NFT_NDPI_FLAG_RE            0x40U
// #define NFT_NDPI_FLAG_EMPTY         0x80U
// #define NFT_NDPI_FLAG_INPROGRESS    0x100U
// #define NFT_NDPI_FLAG_JA3S          0x200U
// #define NFT_NDPI_FLAG_JA3C          0x400U
// #define NFT_NDPI_FLAG_TLSFP         0x800U
// #define NFT_NDPI_FLAG_TLSV          0x1000U
// #define NFT_NDPI_FLAG_UNTRACKED     0x2000U
// #define NFT_NDPI_FLAG_PROTOCOL     0x4000U

static int
nftnl_expr_ndpi_snprintf(char *buf, size_t remain,
			uint32_t flags, const struct nftnl_expr *e)
{
	struct nftnl_expr_ndpi *ndpi = nftnl_expr_data(e);
	int ret, offset = 0;

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
            for (l = i = 0; i < NDPI_NUM_BITS; i++) {
                // if (prot_short_str[i] && !prot_disabled[i] && NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0)
                //     printf("%s%s",l++ ? ",":"", prot_short_str[i]);
            }
            if(l == 0) {
                ret = snprintf(buf + offset, remain, "no protos ");
            }
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
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

        // for (t = c = i = 0; i < NDPI_NUM_BITS; i++) {
		//     if (!prot_short_str[i] || prot_disabled[i] || !strncmp(prot_short_str[i],"badproto_",9)) continue;
		//     t++;
		//     if (NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0) c++;
        // }
        // ret = snprintf(buf + offset, remain, "%sndpi ", cinv);
		// SNPRINTF_BUFFER_SIZE(ret, remain, offset);

		if ((ndpi->flags & NFT_NDPI_FLAG_M_PROTO) && !(ndpi->flags & NFT_NDPI_FLAG_P_PROTO)) {
			ret = snprintf(buf + offset, remain, "match-master ");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}
        if (!(ndpi->flags & NFT_NDPI_FLAG_M_PROTO) && (ndpi->flags & NFT_NDPI_FLAG_P_PROTO)) {
			ret = snprintf(buf + offset, remain, "match-proto ");
			SNPRINTF_BUFFER_SIZE(ret, remain, offset);
		}
        // if(!c) return;

	    // if( c == t-1 && 
	    //     !NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags,NDPI_PROTOCOL_UNKNOWN) ) {
	    // 	printf(" all protocols");
	    // 	return;
	    // }
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
             //printf(" protocol%s ",c > 1 ? "s":"");
        }
        // if(c > t/2 + 1) {
	    //     printf("all");
	    //     for (i = 1; i < NDPI_NUM_BITS; i++) {
        //             if (prot_short_str[i] && !prot_disabled[i] && NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) == 0)
		//     	printf(",-%s", prot_short_str[i]);
	    //     }
	    //     return;
	    // }

        // for (l = i = 0; i < NDPI_NUM_BITS; i++) {
        //         if (prot_short_str[i] && !prot_disabled[i] && NDPI_COMPARE_PROTOCOL_TO_BITMASK(info->flags, i) != 0)
        //                 printf("%s%s",l++ ? ",":"", prot_short_str[i]);
        // }
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
