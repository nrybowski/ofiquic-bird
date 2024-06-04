#ifndef BIRD_OSPF_DEFS_H
#define BIRD_OSPF_DEFS_H
#include "sysdep/config.h"
#include "lib/net.h"

struct ospf_packet
{
  u8 version;
  u8 type;
  u16 length;
  u32 routerid;
  u32 areaid;
  u16 checksum;
  u8 instance_id;		/* See RFC 6549 */
  u8 autype;			/* Undefined for OSPFv3 */
};

struct ospf_lls
{
  u16 checksum;
  u16 length;
  byte data[0];
};

struct ospf_auth_crypto
{
  u16 zero;
  u8 keyid;
  u8 len;
  u32 csn;			/* Cryptographic sequence number (32-bit) */
};

union ospf_auth2
{
  u8 password[8];
  struct ospf_auth_crypto c32;
};

struct ospf_auth3
{
  u16 type;			/* Authentication type (OSPF3_AUTH_*) */
  u16 length;			/* Authentication trailer length (header + data) */
  u16 reserved;
  u16 sa_id;			/* Security association identifier (key_id) */
  u64 csn;			/* Cryptographic sequence number (64-bit) */
  byte data[0];			/* Authentication data */
};


/* Packet types */
#define HELLO_P		1	/* Hello */
#define DBDES_P		2	/* Database description */
#define LSREQ_P		3	/* Link state request */
#define LSUPD_P		4	/* Link state update */
#define LSACK_P		5	/* Link state acknowledgement */


#define DBDES_I		4	/* Init bit */
#define DBDES_M		2	/* More bit */
#define DBDES_MS	1	/* Master/Slave bit */
#define DBDES_IMMS	(DBDES_I | DBDES_M | DBDES_MS)


/* OSPFv3 LSA Types / LSA Function Codes */
/* https://www.iana.org/assignments/ospfv3-parameters/ospfv3-parameters.xhtml#ospfv3-parameters-3 */
#define LSA_T_RT		0x2001
#define LSA_T_NET		0x2002
#define LSA_T_SUM_NET		0x2003
#define LSA_T_SUM_RT		0x2004
#define LSA_T_EXT		0x4005
#define LSA_T_NSSA		0x2007
#define LSA_T_LINK		0x0008
#define LSA_T_PREFIX		0x2009
#define LSA_T_GR		0x000B
#define LSA_T_RI_		0x000C
#define LSA_T_RI_LINK		0x800C
#define LSA_T_RI_AREA		0xA00C
#define LSA_T_RI_AS		0xC00C
#define LSA_T_OPAQUE_		0x1FFF
#define LSA_T_OPAQUE_LINK	0x9FFF
#define LSA_T_OPAQUE_AREA	0xBFFF
#define LSA_T_OPAQUE_AS	 	0xDFFF

#define LSA_T_V2_OPAQUE_	0x0009
#define LSA_T_V2_MASK		0x00ff

/* OSPFv2 Opaque LSA Types */
/* https://www.iana.org/assignments/ospf-opaque-types/ospf-opaque-types.xhtml#ospf-opaque-types-2 */
#define LSA_OT_GR		0x03
#define LSA_OT_RI		0x04

#define LSA_FUNCTION_MASK	0x1FFF
#define LSA_FUNCTION(type)	((type) & LSA_FUNCTION_MASK)

#define LSA_UBIT		0x8000

#define LSA_SCOPE_LINK		0x0000
#define LSA_SCOPE_AREA		0x2000
#define LSA_SCOPE_AS		0x4000
#define LSA_SCOPE_RES		0x6000
#define LSA_SCOPE_MASK		0x6000
#define LSA_SCOPE(type)		((type) & LSA_SCOPE_MASK)
#define LSA_SCOPE_ORDER(type)	(((type) >> 13) & 0x3)


#define LSA_MAXAGE	3600	/* 1 hour */
#define LSA_CHECKAGE	300	/* 5 minutes */
#define LSA_MAXAGEDIFF	900	/* 15 minutes */

#define LSA_ZEROSEQNO	((s32) 0x80000000)
#define LSA_INITSEQNO	((s32) 0x80000001)
#define LSA_MAXSEQNO	((s32) 0x7fffffff)

#define LSA_METRIC_MASK  0x00FFFFFF
#define LSA_OPTIONS_MASK 0x00FFFFFF


#define LSART_PTP	1
#define LSART_NET	2
#define LSART_STUB	3
#define LSART_VLNK	4

#define LSA_RT2_LINKS	0x0000FFFF

#define LSA_SUM2_TOS	0xFF000000

#define LSA_EXT2_TOS	0x7F000000
#define LSA_EXT2_EBIT	0x80000000

#define LSA_EXT3_EBIT	0x04000000
#define LSA_EXT3_FBIT	0x02000000
#define LSA_EXT3_TBIT	0x01000000

/* OSPF Grace LSA (GR) TLVs */
/* https://www.iana.org/assignments/ospfv2-parameters/ospfv2-parameters.xhtml#ospfv2-parameters-13 */
#define LSA_GR_PERIOD		1
#define LSA_GR_REASON		2
#define LSA_GR_ADDRESS		3

/* OSPF Router Information (RI) TLVs */
/* https://www.iana.org/assignments/ospf-parameters/ospf-parameters.xhtml#ri-tlv */
#define LSA_RI_RIC		1
#define LSA_RI_RFC		2

/* OSPF Router Informational Capability Bits */
/* https://www.iana.org/assignments/ospf-parameters/ospf-parameters.xhtml#router-informational-capability */
#define LSA_RIC_GR_CAPABLE	0
#define LSA_RIC_GR_HELPER	1
#define LSA_RIC_STUB_ROUTER	2


struct ospf_lsa_header
{
  u16 age;			/* LS Age */
  u16 type_raw;			/* Type, mixed with options on OSPFv2 */

  u32 id;
  u32 rt;			/* Advertising router */
  s32 sn;			/* LS Sequence number */
  u16 checksum;
  u16 length;
};


/* In OSPFv2, options are embedded in higher half of type_raw */
static inline u8 lsa_get_options(struct ospf_lsa_header *lsa)
{ return lsa->type_raw >> 8; }

static inline void lsa_set_options(struct ospf_lsa_header *lsa, u16 options)
{ lsa->type_raw = (lsa->type_raw & 0xff) | (options << 8); }


struct ospf_lsa_rt
{
  u32 options;	/* VEB flags, mixed with link count for OSPFv2 and options for OSPFv3 */
};

struct ospf_lsa_rt2_link
{
  u32 id;
  u32 data;
#ifdef CPU_BIG_ENDIAN
  u8 type;
  u8 no_tos;
  u16 metric;
#else
  u16 metric;
  u8 no_tos;
  u8 type;
#endif
};

struct ospf_lsa_rt2_tos
{
#ifdef CPU_BIG_ENDIAN
  u8 tos;
  u8 padding;
  u16 metric;
#else
  u16 metric;
  u8 padding;
  u8 tos;
#endif
};

struct ospf_lsa_rt3_link
{
#ifdef CPU_BIG_ENDIAN
  u8 type;
  u8 padding;
  u16 metric;
#else
  u16 metric;
  u8 padding;
  u8 type;
#endif
  u32 lif;	/* Local interface ID */
  u32 nif;	/* Neighbor interface ID */
  u32 id;	/* Neighbor router ID */
};


struct ospf_lsa_net
{
  u32 optx;	/* Netmask for OSPFv2, options for OSPFv3 */
  u32 routers[];
};

struct ospf_lsa_sum2
{
  u32 netmask;
  u32 metric;
};

struct ospf_lsa_sum3_net
{
  u32 metric;
  u32 prefix[];
};

struct ospf_lsa_sum3_rt
{
  u32 options;
  u32 metric;
  u32 drid;
};

struct ospf_lsa_ext2
{
  u32 netmask;
  u32 metric;
  u32 fwaddr;
  u32 tag;
};

struct ospf_lsa_ext3
{
  u32 metric;
  u32 rest[];
};

struct ospf_lsa_ext_local
{
  net_addr net;
  ip_addr fwaddr;
  u32 metric, ebit, fbit, tag, propagate, downwards;
  u8 pxopts;
};

struct ospf_lsa_link
{
  u32 options;
  ip6_addr lladdr;
  u32 pxcount;
  u32 rest[];
};

struct ospf_lsa_prefix
{
#ifdef CPU_BIG_ENDIAN
  u16 pxcount;
  u16 ref_type;
#else
  u16 ref_type;
  u16 pxcount;
#endif
  u32 ref_id;
  u32 ref_rt;
  u32 rest[];
};

struct ospf_tlv
{
#ifdef CPU_BIG_ENDIAN
  u16 type;
  u16 length;
#else
  u16 length;
  u16 type;
#endif
  u32 data[];
};


static inline uint
lsa_net_count(struct ospf_lsa_header *lsa)
{
  return (lsa->length - sizeof(struct ospf_lsa_header) - sizeof(struct ospf_lsa_net))
    / sizeof(u32);
}
#endif
