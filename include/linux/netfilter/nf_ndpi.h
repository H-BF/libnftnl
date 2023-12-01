#ifndef _NETFILTER_NF_NDPI_H
#define _NETFILTER_NF_NDPI_H

#define NFT_NDPI_FLAG_INVERT        0x1U
#define NFT_NDPI_FLAG_ERROR         0x2U
#define NFT_NDPI_FLAG_M_PROTO       0x4U
#define NFT_NDPI_FLAG_P_PROTO       0x8U
#define NFT_NDPI_FLAG_HAVE_MASTER   0x10U
#define NFT_NDPI_FLAG_HOST          0x20U
#define NFT_NDPI_FLAG_RE            0x40U
#define NFT_NDPI_FLAG_EMPTY         0x80U
#define NFT_NDPI_FLAG_INPROGRESS    0x100U
#define NFT_NDPI_FLAG_JA3S          0x200U
#define NFT_NDPI_FLAG_JA3C          0x400U
#define NFT_NDPI_FLAG_TLSFP         0x800U
#define NFT_NDPI_FLAG_TLSV          0x1000U
#define NFT_NDPI_FLAG_UNTRACKED     0x2000U

#define NFT_NDPI_HOSTNAME_LEN_MAX   128
#define NDPI_NUM_BITS 512


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


#endif /* _NETFILTER_NF_NDPI_H */