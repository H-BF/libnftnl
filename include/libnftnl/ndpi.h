#ifndef _LIBNFTNL_NDPI_H_
#define _LIBNFTNL_NDPI_H_

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>

#define NDPI_GIT_RELEASE "4.9.0-4813-90514cb2"

#define NFT_NDPI_FLAG_INVERT        0x1U
#define NFT_NDPI_FLAG_ERROR         0x2U
#define NFT_NDPI_FLAG_M_PROTO       0x4U
#define NFT_NDPI_FLAG_P_PROTO       0x8U
#define NFT_NDPI_FLAG_HAVE_MASTER   0x10U
#define NFT_NDPI_FLAG_HOST          0x20U
#define NFT_NDPI_FLAG_RE            0x40U
#define NFT_NDPI_FLAG_EMPTY         0x80U
#define NFT_NDPI_FLAG_PROTO         0x100U
#define NFT_NDPI_FLAG_INPROGRESS    0x200U
#define NFT_NDPI_FLAG_JA3S          0x400U
#define NFT_NDPI_FLAG_JA3C          0x800U
#define NFT_NDPI_FLAG_TLSFP         0x1000U
#define NFT_NDPI_FLAG_TLSV          0x2000U
#define NFT_NDPI_FLAG_UNTRACKED     0x4000U

#define NFT_NDPI_PROTOCMD_LEN_MAX   128

typedef u_int32_t ndpi_ndpi_mask;

#define NDPI_NUM_BITS              512
#define NDPI_NUM_BITS_MASK         (512-1)

#define NDPI_BITS /* 32 */ (sizeof(ndpi_ndpi_mask) * 8 /* number of bits in a byte */)        /* bits per mask */
#define howmanybits(x, y)   (((x)+((y)-1))/(y))

#define NDPI_SET(p, n)    ((p)->fds_bits[(n)/NDPI_BITS] |=  (1ul << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_CLR(p, n)    ((p)->fds_bits[(n)/NDPI_BITS] &= ~(1ul << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_ISSET(p, n)  ((p)->fds_bits[(n)/NDPI_BITS] &   (1ul << (((u_int32_t)n) % NDPI_BITS)))
#define NDPI_ZERO(p)      memset((char *)(p), 0, sizeof(*(p)))
#define NDPI_ONE(p)       memset((char *)(p), 0xFF, sizeof(*(p)))

#define NDPI_NUM_FDS_BITS     howmanybits(NDPI_NUM_BITS, NDPI_BITS)

/* NDPI_PROTO_BITMASK_STRUCT */
typedef struct ndpi_protocol_bitmask_struct {
  ndpi_ndpi_mask fds_bits[NDPI_NUM_FDS_BITS];
} ndpi_protocol_bitmask_struct_t;

#define NDPI_PROTOCOL_BITMASK ndpi_protocol_bitmask_struct_t

#define NFT_NDPI_HOSTNAME_LEN_MAX   (256 - sizeof(NDPI_PROTOCOL_BITMASK) - sizeof(unsigned short int)-sizeof(void *))


#define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value) NDPI_ISSET(&bmask, value & NDPI_NUM_BITS_MASK)
#define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value)     NDPI_SET(&bmask,   value & NDPI_NUM_BITS_MASK)
#define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value)   NDPI_CLR(&bmask,   value & NDPI_NUM_BITS_MASK)

#define NDPI_PROTOCOL_UNKNOWN 0

/**
 * enum nft_ndpi_attributes - nf_tables ndpi expression netlink attributes
 *
 * @NFTA_NDPI_PROTO: ndpi known protocol (NLA_U32)
 * @NFTA_NDPI_FLAGS: ndpi flags (NLA_U16)
 * @NFTA_NDPI_HOSTNAME: ndpi hostname (NLA_STRING)
 */
enum nft_ndpi_attributes
{
    NFTA_NDPI_UNSPEC,
    NFTA_NDPI_PROTO,
    NFTA_NDPI_FLAGS,
    NFTA_NDPI_HOSTNAME,
    __NFTA_NDPI_MAX,
};

#define NFTA_NDPI_MAX (__NFTA_NDPI_MAX - 1)

enum nft_ndpi_error_codes
{
    NFT_NDPI_NO_ERR = 0,
    NFT_NDPI_NO_KERNEL_MODULE,
    NFT_NDPI_NO_KERNEL_MODULE_VERSION,
    NFT_NDPI_KERNEL_MODULE_VERSION_MISSMATCH
};

static inline int nft_ndpi_get_protos(char **prot_short_str, char* prot_disabled)
{

	char buf[128], *c,pname[32], mark[32];
	uint32_t index;
    int ret = NFT_NDPI_NO_ERR;

	FILE *f_proto = fopen("/proc/net/xt_ndpi/proto", "r");

	if(!f_proto)
		return NFT_NDPI_NO_KERNEL_MODULE;

	pname[0] = '\0';
	index = 0;

	while(!feof(f_proto))
    {
		c = fgets(buf, sizeof(buf) - 1, f_proto);
		if(!c) break;
		if(buf[0] == '#') {
			if(!pname[0] && !strncmp(buf, "#id", 3)) {
			    char *vs;
			    vs = strchr(buf, '\n');
			    if(vs) *vs = '\0';
			    vs = strstr(buf, "#version");
			    if(!vs){
                    ret = NFT_NDPI_NO_KERNEL_MODULE_VERSION;
                    break;
                }

			    if(!strstr(vs + 8, NDPI_GIT_RELEASE)){
                    ret = NFT_NDPI_KERNEL_MODULE_VERSION_MISSMATCH;
                    break;
                }
			    pname[0] = ' ';
			}
			continue;
		}
		if(!pname[0]) continue;
		if(sscanf(buf, "%x %s %s", &index, mark, pname) != 3) continue;
		if(index >= NDPI_NUM_BITS) continue;
		prot_disabled[index] = strncmp(mark, "disable", 7) == 0;
		prot_short_str[index] = strdup(pname);
	}

	fclose(f_proto);

	if(index >= NDPI_NUM_BITS)
        ret = NFT_NDPI_KERNEL_MODULE_VERSION_MISSMATCH;

    return ret;
}

static inline int NDPI_BITMASK_IS_EMPTY(NDPI_PROTOCOL_BITMASK a) {
	int i;

	for(i=0; i<NDPI_NUM_FDS_BITS; i++)
		if(a.fds_bits[i] != 0)
			return(0);

	return(1);
}


#endif /* _LIBNFTNL_NDPI_H_ */