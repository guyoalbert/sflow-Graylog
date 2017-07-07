#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <setjmp.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "sflowH.h"
#include "sflow_protoH.h" // sFlow v5

//define DEVEL 1

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#define MAX_SFLOW_EXTENSIONS 8

typedef struct exporter_sflow_s {
	// link chain
	struct exporter_sflow_s *next;

	// generic exporter information
	exporter_info_record_t info;

    uint64_t    packets;            // number of packets sent by this exporter
    uint64_t    flows;              // number of flow records sent by this exporter
    uint32_t    sequence_failure;   // number of sequence failues

	// extension map
	// extension maps are common for all exporters

} exporter_sflow_t;


/* module limited globals */

/*
 * As sflow has no templates, we need to have an extension map for each possible
 * combination of IPv4/IPv6 addresses in all ip fields
 *
 * index id:
 * 0 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4
 * 1 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v4
 * 2 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4
 * 3 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v4
 * 4 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6
 * 5 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v4, EX_ROUTER_IP_v6
 * 6 : EX_NEXT_HOP_v4, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6
 * 7 : EX_NEXT_HOP_v6, EX_NEXT_HOP_BGP_v6, EX_ROUTER_IP_v6
 */

#define SFLOW_NEXT_HOP 	   1
#define SFLOW_NEXT_HOP_BGP 2
#define SFLOW_ROUTER_IP    4


#define YES 1
#define NO 0

/* define my own IP header struct - to ease portability */
struct myiphdr {
		uint8_t version_and_headerLen;
		uint8_t tos;
		uint16_t tot_len;
		uint16_t id;
		uint16_t frag_off;
		uint8_t ttl;
		uint8_t protocol;
		uint16_t check;
		uint32_t saddr;
		uint32_t daddr;
};

/* same for tcp */
struct mytcphdr {
		uint16_t th_sport;		/* source port */
		uint16_t th_dport;		/* destination port */
		uint32_t th_seq;		/* sequence number */
		uint32_t th_ack;		/* acknowledgement number */
		uint8_t th_off_and_unused;
		uint8_t th_flags;
		uint16_t th_win;		/* window */
		uint16_t th_sum;		/* checksum */
		uint16_t th_urp;		/* urgent pointer */
};

/* and UDP */
struct myudphdr {
	uint16_t uh_sport;           /* source port */
	uint16_t uh_dport;           /* destination port */
	uint16_t uh_ulen;            /* udp length */
	uint16_t uh_sum;             /* udp checksum */
};

/* and ICMP */
struct myicmphdr {
	uint8_t type;		/* message type */
	uint8_t code;		/* type sub-code */
	/* ignore the rest */
};

typedef struct _SFForwardingTarget {
	struct _SFForwardingTarget *nxt;
	struct in_addr host;
	uint32_t port;
	struct sockaddr_in addr;
	int sock;
} SFForwardingTarget;

typedef enum { SFLFMT_FULL=0, SFLFMT_PCAP, SFLFMT_LINE } EnumSFLFormat;

typedef struct _SFConfig {
	uint16_t netFlowPeerAS;
	int disableNetFlowScale;
} SFConfig;

/* make the options structure global to the program */

typedef struct _SFSample {
	struct in_addr sourceIP;		// EX_ROUTER_IP_v4
	SFLAddress agent_addr;
	uint32_t agentSubId;

	/* the raw pdu */
	u_char *rawSample;
	uint32_t rawSampleLen;
	u_char *endp;

	/* decode cursor */
	uint32_t *datap;

	uint32_t datagramVersion;
	uint32_t sampleType;
	uint32_t ds_class;
	uint32_t ds_index;

	/* generic interface counter sample */
	SFLIf_counters ifCounters;

	/* sample stream info */
	uint32_t sysUpTime;
	uint32_t sequenceNo;
	uint32_t sampledPacketSize;
	uint32_t samplesGenerated;
	uint32_t meanSkipCount;
	uint32_t samplePool;
	uint32_t dropEvents;

	/* exception handler context */
	jmp_buf env;

	/* the sampled header */
	uint32_t packet_data_tag;
	uint32_t headerProtocol;
	u_char *header;
	int headerLen;
	uint32_t stripped;

	/* header decode */
	int gotIPV4;
	int offsetToIPV4;
	int gotIPV6;				// v6 flag
	int offsetToIPV6;
	struct in_addr dcd_srcIP;	// Common (v4)
	struct in_addr dcd_dstIP;	// Common (v4)
	uint32_t dcd_ipProtocol;	// Common
	uint32_t dcd_ipTos;			// EX_MULIPLE
	uint32_t dcd_ipTTL;
	uint32_t dcd_sport;			// Common
	uint32_t dcd_dport;			// Common
	uint32_t dcd_tcpFlags;		// Common
	uint32_t ip_fragmentOffset;
	uint32_t udp_pduLen;

	/* ports */
	uint32_t inputPortFormat;
	uint32_t outputPortFormat;
	uint32_t inputPort;			// EX_IO_SNMP_4
	uint32_t outputPort;		// EX_IO_SNMP_4

	/* ethernet */
	uint32_t eth_type;
	uint32_t eth_len;
	u_char eth_src[8];			// EX_MAC_1
	u_char eth_dst[8];			// EX_MAC_1

	/* vlan */
	uint32_t in_vlan;			// EX_VLAN
	uint32_t in_priority;
	uint32_t internalPriority;
	uint32_t out_vlan;			// EX_VLAN
	uint32_t out_priority;

	/* extended data fields */
	uint32_t num_extended;
	uint32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096

	/* IP forwarding info */
	SFLAddress nextHop;			// EX_NEXT_HOP_v4, EX_NEXT_HOP_v6
	uint32_t srcMask;			// EX_MULIPLE
	uint32_t dstMask;			// EX_MULIPLE

	/* BGP info */
	SFLAddress bgp_nextHop;		// EX_NEXT_HOP_BGP_v4, EX_NEXT_HOP_BGP_v6
	uint32_t my_as;
	uint32_t src_as;			// EX_AS_4
	uint32_t src_peer_as;
	uint32_t dst_as_path_len;
	uint32_t *dst_as_path;
	/* note: version 4 dst as path segments just get printed, not stored here, however
	 * the dst_peer and dst_as are filled in, since those are used for netflow encoding
	 */
	uint32_t dst_peer_as;
	uint32_t dst_as;			// EX_AS_4
	
	uint32_t communities_len;
	uint32_t *communities;
	uint32_t localpref;

	/* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
	uint32_t src_user_charset;
	uint32_t src_user_len;
	char src_user[SA_MAX_EXTENDED_USER_LEN+1];
	uint32_t dst_user_charset;
	uint32_t dst_user_len;
	char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

	/* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
	uint32_t url_direction;
	uint32_t url_len;
	char url[SA_MAX_EXTENDED_URL_LEN+1];
	uint32_t host_len;
	char host[SA_MAX_EXTENDED_HOST_LEN+1];

	/* mpls */
	SFLAddress mpls_nextHop;

	/* nat */
	SFLAddress nat_src;
	SFLAddress nat_dst;

	/* counter blocks */
	uint32_t statsSamplingInterval;
	uint32_t counterBlockVersion;

#define SFABORT(s, r) longjmp((s)->env, (r))
#define SF_ABORT_EOS 1
#define SF_ABORT_DECODE_ERROR 2
#define SF_ABORT_LENGTH_ERROR 3

	SFLAddress ipsrc;		// Common (v6)
	SFLAddress ipdst;		// Common (v6)
} SFSample;

//int Setup_Extension_Info(exporter_sflow_t	*exporter, int num);

static int printHex(const u_char *a, int len, char *buf, int bufLen, int marker, int bytesPerOutputLine);

static char *IP_to_a(uint32_t ipaddr, char *buf, int buflen);

static inline uint32_t getData32(SFSample *sample);

static inline uint32_t getData32_nobswap(SFSample *sample);

static inline uint64_t getData64(SFSample *sample);

static void writeCountersLine(SFSample *sample);

#ifdef __SUNPRO_C
static void receiveError(SFSample *sample, char *errm, int hexdump);
#pragma does_not_return (receiveError)
#else
static void receiveError(SFSample *sample, char *errm, int hexdump) __attribute__ ((noreturn));
#endif

static inline void skipBytes(SFSample *sample, int skip);

static inline uint32_t sf_log_next32(SFSample *sample, char *fieldName);

static inline uint64_t sf_log_next64(SFSample *sample, char *fieldName);

static inline void sf_log_percentage(SFSample *sample, char *fieldName);

static inline uint32_t getString(SFSample *sample, char *buf, int bufLen);

static inline uint32_t getAddress(SFSample *sample, SFLAddress *address);

static inline char *printTag(uint32_t tag, char *buf, int bufLen);

static inline void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description);

static inline void readSFlowDatagram(SFSample *sample);

static inline void readFlowSample(SFSample *sample, int expanded);

static inline void readCountersSample(SFSample *sample, int expanded);

static inline void readFlowSample_v2v4(SFSample *sample);

static inline void readCountersSample_v2v4(SFSample *sample);

//extern int verbose;
//#define verbose 1
int  verbose;

/* Variable globales */
int sockfdEnvoie;
struct sockaddr_in envoie_addr;

static void LogError(char* format, ...) {
	printf("erreur ............\n");
}




/*_________________---------------------------__________________
	_________________        printHex           __________________
	-----------------___________________________------------------
*/

static u_char bin2hex(int nib) { return (nib < 10) ? ('0' + nib) : ('A' - 10 + nib); }

static int printHex(const u_char *a, int len, char *buf, int bufLen, int marker, int bytesPerOutputLine) {
	int b = 0, i = 0;
	for(; i < len; i++) {
		u_char byte;
		if(b > (bufLen - 10)) break;
		if(marker > 0 && i == marker) {
			buf[b++] = '<';
			buf[b++] = '*';
			buf[b++] = '>';
			buf[b++] = '-';
		}
		byte = a[i];
		buf[b++] = bin2hex(byte >> 4);
		buf[b++] = bin2hex(byte & 0x0f);
		if(i > 0 && (i % bytesPerOutputLine) == 0) buf[b++] = '\n';
		else {
			// separate the bytes with a dash
			if (i < (len - 1)) buf[b++] = '-';
		}
	}
	buf[b] = '\0';
	return b;
}

/*_________________---------------------------__________________
	_________________      IP_to_a              __________________
	-----------------___________________________------------------
*/

static char *IP_to_a(uint32_t ipaddr, char *buf, int buflen) {
	u_char *ip = (u_char *)&ipaddr;
	snprintf(buf, buflen, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
	buf[buflen-1] = '\0';
	return buf;
}

static char *printAddress(SFLAddress *address, char *buf, int bufLen) {
	if(address->type == SFLADDRESSTYPE_IP_V4)
		IP_to_a(address->address.ip_v4.s_addr, buf, bufLen);
	else {
		u_char *b = address->address.ip_v6.s6_addr;
		snprintf(buf, bufLen, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
			b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
	}
	return buf;
}

/*_________________---------------------------__________________
	_________________    sendToGraylog          __________________
	-----------------___________________________------------------
*/

static void sentToGraylog(SFSample *sample) {
	char buff2[3000];
	int n;

	char agentIP[51], srcIP[51], dstIP[51];
	// source
	n = sprintf(buff2, "FLOW,%s,%d,%d,%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,0x%04x,%d,%d,%s,%s,%d,0x%02x,%d,%d,%d,0x%02x,%d,%d,%d\n",
	printAddress(&sample->agent_addr, agentIP, 50),
	sample->inputPort,
	sample->outputPort,
	// layer 2
	sample->eth_src[0],
	sample->eth_src[1],
	sample->eth_src[2],
	sample->eth_src[3],
	sample->eth_src[4],
	sample->eth_src[5],
	sample->eth_dst[0],
	sample->eth_dst[1],
	sample->eth_dst[2],
	sample->eth_dst[3],
	sample->eth_dst[4],
	sample->eth_dst[5],
	sample->eth_type,
	sample->in_vlan,
	sample->out_vlan,
	// layer 3/4
	IP_to_a(sample->dcd_srcIP.s_addr, srcIP, 51),
	IP_to_a(sample->dcd_dstIP.s_addr, dstIP, 51),
	sample->dcd_ipProtocol,
	sample->dcd_ipTos,	
	sample->dcd_ipTTL,
	sample->dcd_sport,
	sample->dcd_dport,
	sample->dcd_tcpFlags,
	// bytes
	sample->sampledPacketSize,
	sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4,
	sample->meanSkipCount);

	sendto(sockfdEnvoie, buff2, n, 0, (struct sockaddr *) &envoie_addr, sizeof(envoie_addr));
}


/*_________________---------------------------__________________
	_________________    writeFlowLine          __________________
	-----------------___________________________------------------
*/

/* permet d'écrire la ligne dans le terminal */
static void writeFlowLine(SFSample *sample) {
char agentIP[51], srcIP[51], dstIP[51];
	// source
	printf("FLOW,%s,%d,%d,",
	printAddress(&sample->agent_addr, agentIP, 50),
	sample->inputPort,
	sample->outputPort);
	// layer 2
	printf("%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,0x%04x,%d,%d",
	sample->eth_src[0],
	sample->eth_src[1],
	sample->eth_src[2],
	sample->eth_src[3],
	sample->eth_src[4],
	sample->eth_src[5],
	sample->eth_dst[0],
	sample->eth_dst[1],
	sample->eth_dst[2],
	sample->eth_dst[3],
	sample->eth_dst[4],
	sample->eth_dst[5],
	sample->eth_type,
	sample->in_vlan,
	sample->out_vlan);
	// layer 3/4
	printf(",IP: %s,%s,%d,0x%02x,%d,%d,%d,0x%02x",
	IP_to_a(sample->dcd_srcIP.s_addr, srcIP, 51),
	IP_to_a(sample->dcd_dstIP.s_addr, dstIP, 51),
	sample->dcd_ipProtocol,
	sample->dcd_ipTos,	
	sample->dcd_ipTTL,
	sample->dcd_sport,
	sample->dcd_dport,
	sample->dcd_tcpFlags);
	// bytes
	printf(",%d,%d,%d\n",
	sample->sampledPacketSize,
	sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4,
	sample->meanSkipCount);

}

/*_________________---------------------------__________________
	_________________    writeCountersLine      __________________
	-----------------___________________________------------------
*/

static void writeCountersLine(SFSample *sample)
{
	// source
	char agentIP[51];
	printf("CNTR,%s,", printAddress(&sample->agent_addr, agentIP, 50));
	printf("%u,%u,%llu,%u,%u,%llu,%u,%u,%u,%u,%u,%u,%llu,%u,%u,%u,%u,%u,%u\n",
	 sample->ifCounters.ifIndex,
	 sample->ifCounters.ifType,
	 (unsigned long long)sample->ifCounters.ifSpeed,
	 sample->ifCounters.ifDirection,
	 sample->ifCounters.ifStatus,
	 (unsigned long long)sample->ifCounters.ifInOctets,
	 sample->ifCounters.ifInUcastPkts,
	 sample->ifCounters.ifInMulticastPkts,
	 sample->ifCounters.ifInBroadcastPkts,
	 sample->ifCounters.ifInDiscards,
	 sample->ifCounters.ifInErrors,
	 sample->ifCounters.ifInUnknownProtos,
	 (unsigned long long)sample->ifCounters.ifOutOctets,
	 sample->ifCounters.ifOutUcastPkts,
	 sample->ifCounters.ifOutMulticastPkts,
	 sample->ifCounters.ifOutBroadcastPkts,
	 sample->ifCounters.ifOutDiscards,
	 sample->ifCounters.ifOutErrors,
	 sample->ifCounters.ifPromiscuousMode);
}

/*_________________---------------------------__________________
	_________________    receiveError           __________________
	-----------------___________________________------------------
*/

static void receiveError(SFSample *sample, char *errm, int hexdump) 
{
	printf("je receive error utilisé");
	char ipbuf[51];
	char scratch[6000];
	char *msg = "";
	char *hex = "";
	uint32_t markOffset = (u_char *)sample->datap - sample->rawSample;
	if(errm) msg = errm;
	if(hexdump) {
		printHex(sample->rawSample, sample->rawSampleLen, scratch, 6000, markOffset, 16);
		//hex = scratch;
	}
	LogError("SFLOW: %s (source IP = %s) %s", msg, IP_to_a(sample->sourceIP.s_addr, ipbuf, 51), hex);

	SFABORT(sample, SF_ABORT_DECODE_ERROR);

}

/*_________________---------------------------__________________
	_________________    lengthCheck            __________________
	-----------------___________________________------------------
*/

static void lengthCheck(SFSample *sample, char *description, u_char *start, int len) {
	uint32_t actualLen = (u_char *)sample->datap - start;
	uint32_t adjustedLen = ((len + 3) >> 2) << 2;
	if(actualLen != adjustedLen) {
		dbg_printf("%s length error (expected %d, found %d)\n", description, len, actualLen);
		LogError("SFLOW: %s length error (expected %d, found %d)", description, len, actualLen);
		SFABORT(sample, SF_ABORT_LENGTH_ERROR);
  }

}

/*_________________---------------------------__________________
	_________________     decodeLinkLayer       __________________
	-----------------___________________________------------------
	store the offset to the start of the ipv4 header in the sequence_number field
	or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

#define NFT_MIN_SIZ (NFT_ETHHDR_SIZ + sizeof(struct myiphdr))

static void decodeLinkLayer(SFSample *sample)
{
	u_char *start = (u_char *)sample->header;
	u_char *end = start + sample->headerLen;
	u_char *ptr = start;
	uint16_t type_len;

	/* assume not found */
	sample->gotIPV4 = NO;

	if(sample->headerLen < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */

	dbg_printf("dstMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
	memcpy(sample->eth_dst, ptr, 6);
	ptr += 6;

	dbg_printf("srcMAC %02x%02x%02x%02x%02x%02x\n", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
	memcpy(sample->eth_src, ptr, 6);
	ptr += 6;
	type_len = (ptr[0] << 8) + ptr[1];
	ptr += 2;

	if(type_len == 0x8100) {
		/* VLAN  - next two bytes */
		uint32_t vlanData = (ptr[0] << 8) + ptr[1];
		uint32_t vlan = vlanData & 0x0fff;
#ifdef DEVEL
		uint32_t priority = vlanData >> 13;
#endif
		ptr += 2;
		/*  _____________________________________ */
		/* |   pri  | c |         vlan-id        | */
		/*  ------------------------------------- */
		/* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
		dbg_printf("decodedVLAN %u\n", vlan);
		dbg_printf("decodedPriority %u\n", priority);
		sample->in_vlan = vlan;
		/* now get the type_len again (next two bytes) */
		type_len = (ptr[0] << 8) + ptr[1];
		ptr += 2;
	}

	/* now we're just looking for IP */
	if(sample->headerLen < NFT_MIN_SIZ) return; /* not enough for an IPv4 header */
	
	/* peek for IPX */
	if(type_len == 0x0200 || type_len == 0x0201 || type_len == 0x0600) {
#define IPX_HDR_LEN 30
#define IPX_MAX_DATA 546
		int ipxChecksum = (ptr[0] == 0xff && ptr[1] == 0xff);
		int ipxLen = (ptr[2] << 8) + ptr[3];
		if(ipxChecksum &&
			 ipxLen >= IPX_HDR_LEN &&
			 ipxLen <= (IPX_HDR_LEN + IPX_MAX_DATA))
			/* we don't do anything with IPX here */
			return;
	} 
	
	if(type_len <= NFT_MAX_8023_LEN) {
		/* assume 802.3+802.2 header */
		/* check for SNAP */
		if(ptr[0] == 0xAA &&
			 ptr[1] == 0xAA &&
			 ptr[2] == 0x03) {
			ptr += 3;
			if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	dbg_printf("VSNAP_OUI %02X-%02X-%02X\n", ptr[0], ptr[1], ptr[2]);
	return; /* no further decode for vendor-specific protocol */
			}
			ptr += 3;
			/* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
			type_len = (ptr[0] << 8) + ptr[1];
			ptr += 2;
		}
		else {
			if (ptr[0] == 0x06 &&
		ptr[1] == 0x06 &&
		(ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the type_len to be IP so we can inline the IP decode below */
	type_len = 0x0800;
			}
			else return;
		}
	}
	
	/* assume type_len is an ethernet-type now */
	sample->eth_type = type_len;

	if(type_len == 0x0800) {
		/* IPV4 */
		if((end - ptr) < sizeof(struct myiphdr)) return;
		/* look at first byte of header.... */
		/*  ___________________________ */
		/* |   version   |    hdrlen   | */
		/*  --------------------------- */
		if((*ptr >> 4) != 4) return; /* not version 4 */
		if((*ptr & 15) < 5) return; /* not IP (hdr len must be 5 quads or more) */
		/* survived all the tests - store the offset to the start of the ip header */
		sample->gotIPV4 = YES;
		sample->offsetToIPV4 = (ptr - start);
	}

	if(type_len == 0x86DD) {
		/* IPV6 */
		/* look at first byte of header.... */
		if((*ptr >> 4) != 6) return; /* not version 6 */
		/* survived all the tests - store the offset to the start of the ip6 header */
		sample->gotIPV6 = YES;
		sample->offsetToIPV6 = (ptr - start);
	}
}


/*_________________---------------------------__________________
	_________________     decodeIPLayer4        __________________
	-----------------___________________________------------------
*/

static void decodeIPLayer4(SFSample *sample, u_char *ptr, uint32_t ipProtocol) {
	u_char *end = sample->header + sample->headerLen;
	if(ptr > (end - 8)) return; // not enough header bytes left
	switch(ipProtocol) {
	case 1: /* ICMP */
	case 58: /* ICMP6 */
		{
			struct myicmphdr icmp;
			memcpy(&icmp, ptr, sizeof(icmp));
			dbg_printf("ICMPType %u\n", icmp.type);
			dbg_printf("ICMPCode %u\n", icmp.code);
			sample->dcd_sport = icmp.type;
			sample->dcd_dport = icmp.code;
		}
		break;
	case 6: /* TCP */
		{
			struct mytcphdr tcp;
			memcpy(&tcp, ptr, sizeof(tcp));
			sample->dcd_sport = ntohs(tcp.th_sport);
			sample->dcd_dport = ntohs(tcp.th_dport);
			sample->dcd_tcpFlags = tcp.th_flags;
			dbg_printf("TCPSrcPort %u\n", sample->dcd_sport);
			dbg_printf("TCPDstPort %u\n",sample->dcd_dport);
			dbg_printf("TCPFlags %u\n", sample->dcd_tcpFlags);
			if(sample->dcd_dport == 80) {
	int headerBytes = (tcp.th_off_and_unused >> 4) * 4;
	ptr += headerBytes;
			}
		}
		break;
	case 17: /* UDP */
		{
			struct myudphdr udp;
			memcpy(&udp, ptr, sizeof(udp));
			sample->dcd_sport = ntohs(udp.uh_sport);
			sample->dcd_dport = ntohs(udp.uh_dport);
			sample->udp_pduLen = ntohs(udp.uh_ulen);
			dbg_printf("UDPSrcPort %u\n", sample->dcd_sport);
			dbg_printf("UDPDstPort %u\n", sample->dcd_dport);
			dbg_printf("UDPBytes %u\n", sample->udp_pduLen);
		}
		break;
	default: /* some other protcol */
		break;
	}
}

/*_________________---------------------------__________________
	_________________     decodeIPV4            __________________
	-----------------___________________________------------------
*/

static void decodeIPV4(SFSample *sample)
{
	if(sample->gotIPV4) {
#ifdef DEVEL
		char buf[51];
#endif
		u_char *ptr = sample->header + sample->offsetToIPV4;
		/* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
			 platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
		struct myiphdr ip;
		memcpy(&ip, ptr, sizeof(ip));
		/* Value copy all ip elements into sample */
		sample->dcd_srcIP.s_addr = ip.saddr;
		sample->dcd_dstIP.s_addr = ip.daddr;
		sample->dcd_ipProtocol = ip.protocol;
		sample->dcd_ipTos = ip.tos;
		sample->dcd_ipTTL = ip.ttl;
		dbg_printf("ip.tot_len %d\n", ntohs(ip.tot_len));
		/* Log out the decoded IP fields */
		dbg_printf("srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf, 51));
		dbg_printf("dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf, 51));
		dbg_printf("IPProtocol %u\n", sample->dcd_ipProtocol);
		dbg_printf("IPTOS %u\n", sample->dcd_ipTos);
		dbg_printf("IPTTL %u\n", sample->dcd_ipTTL);
		/* check for fragments */
		sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
		if(sample->ip_fragmentOffset > 0) {
			dbg_printf("IPFragmentOffset %u\n", sample->ip_fragmentOffset);
		}
		else {
			/* advance the pointer to the next protocol layer */
			/* ip headerLen is expressed as a number of quads */
			ptr += (ip.version_and_headerLen & 0x0f) * 4;
			decodeIPLayer4(sample, ptr, ip.protocol);
		}
	}
}

/*_________________---------------------------__________________
	_________________     decodeIPV6            __________________
	-----------------___________________________------------------
*/

static void decodeIPV6(SFSample *sample)
{
	uint16_t payloadLen;
	uint32_t label;
	uint32_t nextHeader;
	u_char *end = sample->header + sample->headerLen;

	if(sample->gotIPV6) {
		u_char *ptr = sample->header + sample->offsetToIPV6;
		
		// check the version
		{
			int ipVersion = (*ptr >> 4);
			if(ipVersion != 6) {
	dbg_printf("header decode error: unexpected IP version: %d\n", ipVersion);
	return;
			}
		}

		// get the tos (priority)
		sample->dcd_ipTos = *ptr++ & 15;
		dbg_printf("IPTOS %u\n", sample->dcd_ipTos);
		// 24-bit label
		label = *ptr++;
		label <<= 8;
		label += *ptr++;
		label <<= 8;
		label += *ptr++;
		dbg_printf("IP6_label 0x%x\n", label);
		// payload
		payloadLen = (ptr[0] << 8) + ptr[1];
		ptr += 2;
		// if payload is zero, that implies a jumbo payload
		if(payloadLen == 0) dbg_printf("IPV6_payloadLen <jumbo>\n");
		else dbg_printf("IPV6_payloadLen %u\n", payloadLen);

		// next header
		nextHeader = *ptr++;

		// TTL
		sample->dcd_ipTTL = *ptr++;
		dbg_printf("IPTTL %u\n", sample->dcd_ipTTL);

		{// src and dst address
#ifdef DEVEL
			char buf[101];
#endif
			sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
			memcpy(&sample->ipsrc.address, ptr, 16);
			ptr +=16;
			dbg_printf("srcIP6 %s\n", printAddress(&sample->ipsrc, buf, 100));
			sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
			memcpy(&sample->ipdst.address, ptr, 16);
			ptr +=16;
			dbg_printf("dstIP6 %s\n", printAddress(&sample->ipdst, buf, 100));
		}

		// skip over some common header extensions...
		// http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
		while(nextHeader == 0 ||  // hop
		nextHeader == 43 || // routing
		nextHeader == 44 || // fragment
		// nextHeader == 50 || // encryption - don't bother coz we'll not be able to read any further
		nextHeader == 51 || // auth
		nextHeader == 60) { // destination options
			uint32_t optionLen, skip;
			dbg_printf("IP6HeaderExtension: %d\n", nextHeader);
			nextHeader = ptr[0];
			optionLen = 8 * (ptr[1] + 1);  // second byte gives option len in 8-byte chunks, not counting first 8
			skip = optionLen - 2;
			ptr += skip;
			if(ptr > end) return; // ran off the end of the header
		}
		
		// now that we have eliminated the extension headers, nextHeader should have what we want to
		// remember as the ip protocol...
		sample->dcd_ipProtocol = nextHeader;
		dbg_printf("IPProtocol %u\n", sample->dcd_ipProtocol);
		decodeIPLayer4(sample, ptr, sample->dcd_ipProtocol);
	}
}


/*_________________---------------------------__________________
	_________________   read data fns           __________________
	-----------------___________________________------------------
*/

static inline uint32_t getData32(SFSample *sample) {
	if ((u_char *)sample->datap > sample->endp) 
		SFABORT(sample, SF_ABORT_EOS);
	return ntohl(*(sample->datap)++);
} // End of getData32

static inline uint32_t getData32_nobswap(SFSample *sample) {
	if ((u_char *)sample->datap > sample->endp) 
		SFABORT(sample, SF_ABORT_EOS);
	return *(sample->datap)++;
} // End of getData32_nobswap

static inline uint64_t getData64(SFSample *sample) {
uint64_t tmpLo, tmpHi;

	tmpHi = getData32(sample);
	tmpLo = getData32(sample);
	return (tmpHi << 32) + tmpLo;
} // End of getData64

static inline void skipBytes(SFSample *sample, int skip) {
int quads = (skip + 3) / 4;

	sample->datap += quads;
	if ( (u_char *)sample->datap > sample->endp) 
		SFABORT(sample, SF_ABORT_EOS);
} // End of skipBytes

static inline uint32_t sf_log_next32(SFSample *sample, char *fieldName) {
uint32_t val = getData32(sample);

	dbg_printf("%s %u\n", fieldName, val);
	return val;
} // End of sf_log_next32

static inline uint64_t sf_log_next64(SFSample *sample, char *fieldName) {
uint64_t val64 = getData64(sample);

	dbg_printf("%s %llu\n", fieldName, (unsigned long long)val64);
	return val64;
} // End of sf_log_next64

static inline void sf_log_percentage(SFSample *sample, char *fieldName) {
uint32_t hundredths = getData32(sample);

	if ( hundredths == (uint32_t)-1) 
		dbg_printf("%s unknown\n", fieldName);
	else {
#ifdef DEVEL
		float percent = (float)hundredths / 10.0;
#endif
		dbg_printf("%s %.1f\n", fieldName, percent);
	}
} // End of sf_log_percentage


static inline uint32_t getString(SFSample *sample, char *buf, int bufLen) {
uint32_t len, read_len;

	len = getData32(sample);
	// truncate if too long
	read_len = (len >= bufLen) ? (bufLen - 1) : len;
	memcpy(buf, sample->datap, read_len);
	buf[read_len] = '\0';   // null terminate
	skipBytes(sample, len);
	return len;
} // End of getString

static inline uint32_t getAddress(SFSample *sample, SFLAddress *address) {

	address->type = getData32(sample);
	if(address->type == SFLADDRESSTYPE_IP_V4)
		address->address.ip_v4.s_addr = getData32_nobswap(sample);
	else {
		memcpy(&address->address.ip_v6.s6_addr, sample->datap, 16);
		skipBytes(sample, 16);
	}
	return address->type;
} // End of getAddress

static inline char *printTag(uint32_t tag, char *buf, int bufLen) {
	snprintf(buf, bufLen, "%u:%u", (tag >> 12), (tag & 0x00000FFF));
	return buf;
} // End of printTag

static inline void skipTLVRecord(SFSample *sample, uint32_t tag, uint32_t len, char *description) {
#ifdef DEVEL
char buf[51];
#endif

	dbg_printf("skipping unknown %s: 0x%x, %s len=%d\n", description, tag, printTag(tag, buf, 50), len);
	skipBytes(sample, len);
} // End of skipTLVRecord

/*_________________---------------------------__________________
	_________________    readExtendedSwitch     __________________
	-----------------___________________________------------------
*/

static void readExtendedSwitch(SFSample *sample)
{
	dbg_printf("extendedType SWITCH\n");
	sample->in_vlan = getData32(sample);
	sample->in_priority = getData32(sample);
	sample->out_vlan = getData32(sample);
	sample->out_priority = getData32(sample);

	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;
	
	dbg_printf("in_vlan %u\n", sample->in_vlan);
	dbg_printf("in_priority %u\n", sample->in_priority);
	dbg_printf("out_vlan %u\n", sample->out_vlan);
	dbg_printf("out_priority %u\n", sample->out_priority);
}

/*_________________---------------------------__________________
	_________________    readExtendedRouter     __________________
	-----------------___________________________------------------
*/

static void readExtendedRouter(SFSample *sample)
{
#ifdef DEVEL
char buf[51];
#endif

	dbg_printf("extendedType ROUTER\n");
	getAddress(sample, &sample->nextHop);
	sample->srcMask = getData32(sample);
	sample->dstMask = getData32(sample);

	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;

	dbg_printf("nextHop %s\n", printAddress(&sample->nextHop, buf, 50));
	dbg_printf("srcSubnetMask %u\n", sample->srcMask);
	dbg_printf("dstSubnetMask %u\n", sample->dstMask);
}

/*_________________---------------------------__________________
	_________________  readExtendedGateway_v2   __________________
	-----------------___________________________------------------
*/

static void readExtendedGateway_v2(SFSample *sample)
{
	dbg_printf("extendedType GATEWAY\n");

	sample->my_as = getData32(sample);
	sample->src_as = getData32(sample);
	sample->src_peer_as = getData32(sample);
	sample->dst_as_path_len = getData32(sample);
	/* just point at the dst_as_path array */
	if(sample->dst_as_path_len > 0) {
		sample->dst_as_path = sample->datap;
		/* and skip over it in the input */
		skipBytes(sample, sample->dst_as_path_len * 4);
		// fill in the dst and dst_peer fields too
		sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
		sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
	}
	
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
	
	dbg_printf("my_as %u\n", sample->my_as);
	dbg_printf("src_as %u\n", sample->src_as);
	dbg_printf("src_peer_as %u\n", sample->src_peer_as);
	dbg_printf("dst_as %u\n", sample->dst_as);
	dbg_printf("dst_peer_as %u\n", sample->dst_peer_as);
	dbg_printf("dst_as_path_len %u\n", sample->dst_as_path_len);
	if(sample->dst_as_path_len > 0) {
		uint32_t i = 0;
		for(; i < sample->dst_as_path_len; i++) {
			if(i == 0) dbg_printf("dst_as_path ");
			else dbg_printf("-");
			dbg_printf("%u", ntohl(sample->dst_as_path[i]));
		}
		dbg_printf("\n");
	}
}

/*_________________---------------------------__________________
	_________________  readExtendedGateway      __________________
	-----------------___________________________------------------
*/

static void readExtendedGateway(SFSample *sample)
{
#ifdef DEVEL
		char buf[51];
#endif
	uint32_t segments;
	int seg;

	dbg_printf("extendedType GATEWAY\n");

	if(sample->datagramVersion >= 5) {
		getAddress(sample, &sample->bgp_nextHop);
		dbg_printf("bgp_nexthop %s\n", printAddress(&sample->bgp_nextHop, buf, 50));
	}

	sample->my_as = getData32(sample);
	sample->src_as = getData32(sample);
	sample->src_peer_as = getData32(sample);
	dbg_printf("my_as %u\n", sample->my_as);
	dbg_printf("src_as %u\n", sample->src_as);
	dbg_printf("src_peer_as %u\n", sample->src_peer_as);
	segments = getData32(sample);
	if(segments > 0) {
		dbg_printf("dst_as_path ");
		for(seg = 0; seg < segments; seg++) {
			uint32_t seg_type;
			uint32_t seg_len;
			int i;
			seg_type = getData32(sample);
			seg_len = getData32(sample);
			for(i = 0; i < seg_len; i++) {
	uint32_t asNumber;
	asNumber = getData32(sample);
	/* mark the first one as the dst_peer_as */
	if(i == 0 && seg == 0) sample->dst_peer_as = asNumber;
	else dbg_printf("-");
	/* make sure the AS sets are in parentheses */
	if(i == 0 && seg_type == SFLEXTENDED_AS_SET) dbg_printf("(");
	dbg_printf("%u", asNumber);
	/* mark the last one as the dst_as */
	if(seg == (segments - 1) && i == (seg_len - 1)) sample->dst_as = asNumber;
			}
			if(seg_type == SFLEXTENDED_AS_SET) dbg_printf(")");
		}
		dbg_printf("\n");
	}
	dbg_printf("dst_as %u\n", sample->dst_as);
	dbg_printf("dst_peer_as %u\n", sample->dst_peer_as);

	sample->communities_len = getData32(sample);
	/* just point at the communities array */
	if(sample->communities_len > 0) sample->communities = sample->datap;
	/* and skip over it in the input */
	skipBytes(sample, sample->communities_len * 4);
 
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
	if(sample->communities_len > 0) {
		int j = 0;
		for(; j < sample->communities_len; j++) {
			if(j == 0) dbg_printf("BGP_communities ");
			else dbg_printf("-");
			dbg_printf("%u", ntohl(sample->communities[j]));
		}
		dbg_printf("\n");
	}

	sample->localpref = getData32(sample);
	dbg_printf("BGP_localpref %u\n", sample->localpref);

}

/*_________________---------------------------__________________
	_________________    readExtendedUser       __________________
	-----------------___________________________------------------
*/

static void readExtendedUser(SFSample *sample)
{
	dbg_printf("extendedType USER\n");

	if(sample->datagramVersion >= 5) {
		sample->src_user_charset = getData32(sample);
		dbg_printf("src_user_charset %d\n", sample->src_user_charset);
	}

	sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN);

	if(sample->datagramVersion >= 5) {
		sample->dst_user_charset = getData32(sample);
		dbg_printf("dst_user_charset %d\n", sample->dst_user_charset);
	}

	sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN);

	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;
	
	dbg_printf("src_user %s\n", sample->src_user);
	dbg_printf("dst_user %s\n", sample->dst_user);
}

/*_________________---------------------------__________________
	_________________    readExtendedUrl        __________________
	-----------------___________________________------------------
*/

static void readExtendedUrl(SFSample *sample)
{
	dbg_printf("extendedType URL\n");

	sample->url_direction = getData32(sample);
	dbg_printf("url_direction %u\n", sample->url_direction);
	sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN);
	dbg_printf("url %s\n", sample->url);
	if(sample->datagramVersion >= 5) {
		sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN);
		dbg_printf("host %s\n", sample->host);
	}
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
	_________________       mplsLabelStack      __________________
	-----------------___________________________------------------
*/

static void mplsLabelStack(SFSample *sample, char *fieldName)
{
	SFLLabelStack lstk;
	uint32_t lab;
	lstk.depth = getData32(sample);
	/* just point at the lablelstack array */
	if(lstk.depth > 0) 
		lstk.stack = (uint32_t *)sample->datap;
	else
		lstk.stack = NULL;
	/* and skip over it in the input */
	skipBytes(sample, lstk.depth * 4);
 
	if(lstk.depth > 0) {
		int j = 0;
		for(; j < lstk.depth; j++) {
			if(j == 0) dbg_printf("%s ", fieldName);
			else dbg_printf("-");
			lab = ntohl(lstk.stack[j]);
			dbg_printf("%u.%u.%u.%u",
			 (lab >> 12),     // label
			 (lab >> 9) & 7,  // experimental
			 (lab >> 8) & 1,  // bottom of stack
			 (lab &  255));   // TTL
		}
		dbg_printf("\n");
	}
}

/*_________________---------------------------__________________
	_________________    readExtendedMpls       __________________
	-----------------___________________________------------------
*/

static void readExtendedMpls(SFSample *sample)
{
#ifdef DEVEL
		char buf[51];
#endif
	dbg_printf("extendedType MPLS\n");
	getAddress(sample, &sample->mpls_nextHop);
	dbg_printf("mpls_nexthop %s\n", printAddress(&sample->mpls_nextHop, buf, 50));

	mplsLabelStack(sample, "mpls_input_stack");
	mplsLabelStack(sample, "mpls_output_stack");
	
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
	_________________    readExtendedNat        __________________
	-----------------___________________________------------------
*/

static void readExtendedNat(SFSample *sample)
{
#ifdef DEVEL
		char buf[51];
#endif
	dbg_printf("extendedType NAT\n");
	getAddress(sample, &sample->nat_src);
	dbg_printf("nat_src %s\n", printAddress(&sample->nat_src, buf, 50));
	getAddress(sample, &sample->nat_dst);
	dbg_printf("nat_dst %s\n", printAddress(&sample->nat_dst, buf, 50));
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}


/*_________________---------------------------__________________
	_________________    readExtendedMplsTunnel __________________
	-----------------___________________________------------------
*/

static void readExtendedMplsTunnel(SFSample *sample)
{
#define SA_MAX_TUNNELNAME_LEN 100
	char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
	uint32_t tunnel_id, tunnel_cos;
	
	if(getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN) > 0)
		dbg_printf("mpls_tunnel_lsp_name %s\n", tunnel_name);
	tunnel_id = getData32(sample);
	dbg_printf("mpls_tunnel_id %u\n", tunnel_id);
	tunnel_cos = getData32(sample);
	dbg_printf("mpls_tunnel_cos %u\n", tunnel_cos);
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
	_________________    readExtendedMplsVC     __________________
	-----------------___________________________------------------
*/

static void readExtendedMplsVC(SFSample *sample)
{
#define SA_MAX_VCNAME_LEN 100
	char vc_name[SA_MAX_VCNAME_LEN+1];
	uint32_t vll_vc_id, vc_cos;
	if(getString(sample, vc_name, SA_MAX_VCNAME_LEN) > 0)
		dbg_printf("mpls_vc_name %s\n", vc_name);
	vll_vc_id = getData32(sample);
	dbg_printf("mpls_vll_vc_id %u\n", vll_vc_id);
	vc_cos = getData32(sample);
	dbg_printf("mpls_vc_cos %u\n", vc_cos);
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
	_________________    readExtendedMplsFTN    __________________
	-----------------___________________________------------------
*/

static void readExtendedMplsFTN(SFSample *sample)
{
#define SA_MAX_FTN_LEN 100
	char ftn_descr[SA_MAX_FTN_LEN+1];
	uint32_t ftn_mask;
	if(getString(sample, ftn_descr, SA_MAX_FTN_LEN) > 0)
		dbg_printf("mpls_ftn_descr %s\n", ftn_descr);
	ftn_mask = getData32(sample);
	dbg_printf("mpls_ftn_mask %u\n", ftn_mask);
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
	_________________  readExtendedMplsLDP_FEC  __________________
	-----------------___________________________------------------
*/

static void readExtendedMplsLDP_FEC(SFSample *sample)
{
#ifdef DEVEL
	uint32_t fec_addr_prefix_len = getData32(sample);
#endif
	dbg_printf("mpls_fec_addr_prefix_len %u\n", fec_addr_prefix_len);
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
	_________________  readExtendedVlanTunnel   __________________
	-----------------___________________________------------------
*/

static void readExtendedVlanTunnel(SFSample *sample)
{
	uint32_t lab;
	SFLLabelStack lstk;
	lstk.depth = getData32(sample);
	/* just point at the lablelstack array */
	if(lstk.depth > 0) 
		lstk.stack = (uint32_t *)sample->datap;
	else
		lstk.stack = NULL;
	/* and skip over it in the input */
	skipBytes(sample, lstk.depth * 4);
 
	if(lstk.depth > 0) {
		int j = 0;
		for(; j < lstk.depth; j++) {
			if(j == 0) dbg_printf("vlan_tunnel ");
			else dbg_printf("-");
			lab = ntohl(lstk.stack[j]);
			dbg_printf("0x%04x.%u.%u.%u",
			 (lab >> 16),       // TPI
			 (lab >> 13) & 7,   // priority
			 (lab >> 12) & 1,   // CFI
			 (lab & 4095));     // VLAN
		}
		dbg_printf("\n");
	}
	sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
	_________________    readExtendedProcess    __________________
	-----------------___________________________------------------
*/

static void readExtendedProcess(SFSample *sample)
{
	char pname[51];
	uint32_t num_processes, i;
	dbg_printf("extendedType process\n");
	num_processes = getData32(sample);
	for(i = 0; i < num_processes; i++) {
#ifdef DEVEL
		uint32_t pid = getData32(sample);
#endif
		if(getString(sample, pname, 50) > 0) dbg_printf("pid %u %s\n", pid, pname);
		else dbg_printf("pid %u <no_process_name>\n", pid);
	}
}

/*_________________---------------------------__________________
	_________________  readFlowSample_header    __________________
	-----------------___________________________------------------
*/

static void readFlowSample_header(SFSample *sample) {
	dbg_printf("flowSampleType HEADER\n");
	sample->headerProtocol = getData32(sample);
	dbg_printf("headerProtocol %u\n", sample->headerProtocol);
	sample->sampledPacketSize = getData32(sample);
	dbg_printf("sampledPacketSize %u\n", sample->sampledPacketSize);
	if(sample->datagramVersion > 4) {
		// stripped count introduced in sFlow version 5
		sample->stripped = getData32(sample);
		dbg_printf("strippedBytes %u\n", sample->stripped);
	}
	sample->headerLen = getData32(sample);
	dbg_printf("headerLen %u\n", sample->headerLen);
	
	sample->header = (u_char *)sample->datap; /* just point at the header */
	skipBytes(sample, sample->headerLen);
	{
		char scratch[2000];
		printHex(sample->header, sample->headerLen, scratch, 2000, 0, 2000);
		dbg_printf("headerBytes %s\n", scratch);
	}
	
	switch(sample->headerProtocol) {
		/* the header protocol tells us where to jump into the decode */
	case SFLHEADER_ETHERNET_ISO8023:
		decodeLinkLayer(sample);
		break;
	case SFLHEADER_IPv4: 
		sample->gotIPV4 = YES;
		sample->offsetToIPV4 = 0;
		break;
	case SFLHEADER_ISO88024_TOKENBUS:
	case SFLHEADER_ISO88025_TOKENRING:
	case SFLHEADER_FDDI:
	case SFLHEADER_FRAME_RELAY:
	case SFLHEADER_X25:
	case SFLHEADER_PPP:
	case SFLHEADER_SMDS:
	case SFLHEADER_AAL5:
	case SFLHEADER_AAL5_IP:
	case SFLHEADER_IPv6:
	case SFLHEADER_MPLS:
		dbg_printf("NO_DECODE headerProtocol=%d\n", sample->headerProtocol);
		break;
	default:
		LogError("SFLOW: undefined headerProtocol = %d", sample->headerProtocol);
		exit(-12);
	}
	
	if(sample->gotIPV4) {
		// report the size of the original IPPdu (including the IP header)
		dbg_printf("IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV4);
		decodeIPV4(sample);
	}
	else if(sample->gotIPV6) {
		// report the size of the original IPPdu (including the IP header)
		dbg_printf("IPSize %d\n",  sample->sampledPacketSize - sample->stripped - sample->offsetToIPV6);
		decodeIPV6(sample);
	}

}

/*_________________---------------------------__________________
	_________________  readFlowSample_ethernet  __________________
	-----------------___________________________------------------
*/

static void readFlowSample_ethernet(SFSample *sample)
{
	u_char *p;
	dbg_printf("flowSampleType ETHERNET\n");
	sample->eth_len = getData32(sample);
	memcpy(sample->eth_src, sample->datap, 6);
	skipBytes(sample, 6);
	memcpy(sample->eth_dst, sample->datap, 6);
	skipBytes(sample, 6);
	sample->eth_type = getData32(sample);
	dbg_printf("ethernet_type %u\n", sample->eth_type);
	dbg_printf("ethernet_len %u\n", sample->eth_len);
	p = sample->eth_src;
	dbg_printf("ethernet_src %02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
	p = sample->eth_dst;
	dbg_printf("ethernet_dst %02x%02x%02x%02x%02x%02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);
}


/*_________________---------------------------__________________
	_________________    readFlowSample_IPv4    __________________
	-----------------___________________________------------------
*/

static void readFlowSample_IPv4(SFSample *sample)
{
	dbg_printf("flowSampleType IPV4\n");
	sample->headerLen = sizeof(SFLSampled_ipv4);
	sample->header = (u_char *)sample->datap; /* just point at the header */
	skipBytes(sample, sample->headerLen);
	{
#ifdef DEVEL
		char buf[51];
#endif
		SFLSampled_ipv4 nfKey;
		memcpy(&nfKey, sample->header, sizeof(nfKey));
		sample->sampledPacketSize = ntohl(nfKey.length);
		dbg_printf("sampledPacketSize %u\n", sample->sampledPacketSize); 
		dbg_printf("IPSize %d\n",  sample->sampledPacketSize);
		sample->dcd_srcIP = nfKey.src_ip;
		sample->dcd_dstIP = nfKey.dst_ip;
		sample->dcd_ipProtocol = ntohl(nfKey.protocol);
		sample->dcd_ipTos = ntohl(nfKey.tos);
		dbg_printf("srcIP %s\n", IP_to_a(sample->dcd_srcIP.s_addr, buf, 51));
		dbg_printf("dstIP %s\n", IP_to_a(sample->dcd_dstIP.s_addr, buf, 51));
		dbg_printf("IPProtocol %u\n", sample->dcd_ipProtocol);
		dbg_printf("IPTOS %u\n", sample->dcd_ipTos);
		sample->dcd_sport = ntohl(nfKey.src_port);
		sample->dcd_dport = ntohl(nfKey.dst_port);
		switch(sample->dcd_ipProtocol) {
		case 1: /* ICMP */
			dbg_printf("ICMPType %u\n", sample->dcd_dport);
			/* not sure about the dest port being icmp type
	 - might be that src port is icmp type and dest
	 port is icmp code.  Still, have seen some
	 implementations where src port is 0 and dst
	 port is the type, so it may be safer to
	 assume that the destination port has the type */
			break;
		case 6: /* TCP */
			dbg_printf("TCPSrcPort %u\n", sample->dcd_sport);
			dbg_printf("TCPDstPort %u\n", sample->dcd_dport);
			sample->dcd_tcpFlags = ntohl(nfKey.tcp_flags);
			dbg_printf("TCPFlags %u\n", sample->dcd_tcpFlags);
			break;
		case 17: /* UDP */
			dbg_printf("UDPSrcPort %u\n", sample->dcd_sport);
			dbg_printf("UDPDstPort %u\n", sample->dcd_dport);
			break;
		default: /* some other protcol */
			break;
		}
	}
}

/*_________________---------------------------__________________
	_________________    readFlowSample_IPv6    __________________
	-----------------___________________________------------------
*/

static void readFlowSample_IPv6(SFSample *sample)
{
	dbg_printf("flowSampleType IPV6\n");
	sample->header = (u_char *)sample->datap; /* just point at the header */
	sample->headerLen = sizeof(SFLSampled_ipv6);
	skipBytes(sample, sample->headerLen);
	{
		SFLSampled_ipv6 nfKey6;
		memcpy(&nfKey6, sample->header, sizeof(nfKey6));
		sample->sampledPacketSize = ntohl(nfKey6.length);
		dbg_printf("sampledPacketSize %u\n", sample->sampledPacketSize); 
	}
	/* bug: more decode to do here */
}

/*_________________---------------------------__________________
	_________________    readFlowSample_v2v4    __________________
	-----------------___________________________------------------
*/

static void readFlowSample_v2v4(SFSample *sample) {
	dbg_printf("sampleType FLOWSAMPLE\n");

	sample->samplesGenerated = getData32(sample);
	dbg_printf("sampleSequenceNo %u\n", sample->samplesGenerated);
	{
		uint32_t samplerId = getData32(sample);
		sample->ds_class = samplerId >> 24;
		sample->ds_index = samplerId & 0x00ffffff;
		dbg_printf("sourceId %u:%u\n", sample->ds_class, sample->ds_index);
	}
	
	sample->meanSkipCount = getData32(sample);
	sample->samplePool = getData32(sample);
	sample->dropEvents = getData32(sample);
	sample->inputPort = getData32(sample);
	sample->outputPort = getData32(sample);
	dbg_printf("meanSkipCount %u\n", sample->meanSkipCount);
	dbg_printf("samplePool %u\n", sample->samplePool);
	dbg_printf("dropEvents %u\n", sample->dropEvents);
	dbg_printf("inputPort %u\n", sample->inputPort);
	if(sample->outputPort & 0x80000000) {
		uint32_t numOutputs = sample->outputPort & 0x7fffffff;
		if(numOutputs > 0) dbg_printf("outputPort multiple %d\n", numOutputs);
		else dbg_printf("outputPort multiple >1\n");
	}
	else dbg_printf("outputPort %u\n", sample->outputPort);
	
	sample->packet_data_tag = getData32(sample);
	
	switch(sample->packet_data_tag) {
		
	case INMPACKETTYPE_HEADER: readFlowSample_header(sample); break;
	case INMPACKETTYPE_IPV4: readFlowSample_IPv4(sample); break;
	case INMPACKETTYPE_IPV6: readFlowSample_IPv6(sample); break;
	//default: receiveError(sample, "unexpected packet_data_tag", YES); break;
	}

	sample->extended_data_tag = 0;
	{
		uint32_t x;
		sample->num_extended = getData32(sample);
		for(x = 0; x < sample->num_extended; x++) {
			uint32_t extended_tag;
			extended_tag = getData32(sample);
			switch(extended_tag) {
			case INMEXTENDED_SWITCH: 
				readExtendedSwitch(sample); break;
			case INMEXTENDED_ROUTER: 
				readExtendedRouter(sample); break;
			case INMEXTENDED_GATEWAY:
				if(sample->datagramVersion == 2) 
					readExtendedGateway_v2(sample);
				else 
					readExtendedGateway(sample);
				break;
			case INMEXTENDED_USER: 
				readExtendedUser(sample); break;
			case INMEXTENDED_URL: 
				readExtendedUrl(sample); break;
			default: 
				LogError("Unrecognized extended data tag: %u", extended_tag); 
				//receiveError(sample, "unrecognized extended data tag", YES); 
			break;
			}
		}
	}
	
	if ( verbose ) 
		writeFlowLine(sample);
	sentToGraylog(sample);
}

/*_________________---------------------------__________________
	_________________    readFlowSample         __________________
	-----------------___________________________------------------
*/

static void readFlowSample(SFSample *sample, int expanded) {
	uint32_t num_elements, sampleLength;
	u_char *sampleStart;

	dbg_printf("sampleType FLOWSAMPLE\n");
	sampleLength = getData32(sample);
	sampleStart = (u_char *)sample->datap;
	sample->samplesGenerated = getData32(sample);
	dbg_printf("sampleSequenceNo %u\n", sample->samplesGenerated);
	if(expanded) {
		sample->ds_class = getData32(sample);
		sample->ds_index = getData32(sample);
	}
	else {
		uint32_t samplerId = getData32(sample);
		sample->ds_class = samplerId >> 24;
		sample->ds_index = samplerId & 0x00ffffff;
	}
	dbg_printf("sourceId %u:%u\n", sample->ds_class, sample->ds_index);

	sample->meanSkipCount = getData32(sample);
	sample->samplePool = getData32(sample);
	sample->dropEvents = getData32(sample);
	dbg_printf("meanSkipCount %u\n", sample->meanSkipCount);
	dbg_printf("samplePool %u\n", sample->samplePool);
	dbg_printf("dropEvents %u\n", sample->dropEvents);
	if(expanded) {
		sample->inputPortFormat = getData32(sample);
		sample->inputPort = getData32(sample);
		sample->outputPortFormat = getData32(sample);
		sample->outputPort = getData32(sample);
	}
	else {
		uint32_t inp, outp;
		inp = getData32(sample);
		outp = getData32(sample);
		sample->inputPortFormat = inp >> 30;
		sample->outputPortFormat = outp >> 30;
		sample->inputPort = inp & 0x3fffffff;
		sample->outputPort = outp & 0x3fffffff;
	}
	if(sample->inputPortFormat == 3) dbg_printf("inputPort format==3 %u\n", sample->inputPort);
	else if(sample->inputPortFormat == 2) dbg_printf("inputPort multiple %u\n", sample->inputPort);
	else if(sample->inputPortFormat == 1) dbg_printf("inputPort dropCode %u\n", sample->inputPort);
	else if(sample->inputPortFormat == 0) dbg_printf("inputPort %u\n", sample->inputPort);
	if(sample->outputPortFormat == 3) dbg_printf("outputPort format==3 %u\n", sample->outputPort);
	else if(sample->outputPortFormat == 2) dbg_printf("outputPort multiple %u\n", sample->outputPort);
	else if(sample->outputPortFormat == 1) dbg_printf("outputPort dropCode %u\n", sample->outputPort);
	else if(sample->outputPortFormat == 0) dbg_printf("outputPort %u\n", sample->outputPort);

	num_elements = getData32(sample);
	{
		int el;
		for(el = 0; el < num_elements; el++) {
#ifdef DEVEL
			char buf[51];
#endif
			uint32_t tag, length;
			u_char *start;
			tag = getData32(sample);
			dbg_printf("flowBlock_tag %s\n", printTag(tag, buf, 50));
			length = getData32(sample);
			start = (u_char *)sample->datap;

			switch(tag) {
			case SFLFLOW_HEADER:     readFlowSample_header(sample); break;
			case SFLFLOW_ETHERNET:   readFlowSample_ethernet(sample); break;
			case SFLFLOW_IPV4:       readFlowSample_IPv4(sample); break;
			case SFLFLOW_IPV6:       readFlowSample_IPv6(sample); break;
			case SFLFLOW_EX_SWITCH:  readExtendedSwitch(sample); break;
			case SFLFLOW_EX_ROUTER:  readExtendedRouter(sample); break;
			case SFLFLOW_EX_GATEWAY: readExtendedGateway(sample); break;
			case SFLFLOW_EX_USER:    readExtendedUser(sample); break;
			case SFLFLOW_EX_URL:     readExtendedUrl(sample); break;
			case SFLFLOW_EX_MPLS:    readExtendedMpls(sample); break;
			case SFLFLOW_EX_NAT:     readExtendedNat(sample); break;
			case SFLFLOW_EX_MPLS_TUNNEL:  readExtendedMplsTunnel(sample); break;
			case SFLFLOW_EX_MPLS_VC:      readExtendedMplsVC(sample); break;
			case SFLFLOW_EX_MPLS_FTN:     readExtendedMplsFTN(sample); break;
			case SFLFLOW_EX_MPLS_LDP_FEC: readExtendedMplsLDP_FEC(sample); break;
			case SFLFLOW_EX_VLAN_TUNNEL:  readExtendedVlanTunnel(sample); break;
			case SFLFLOW_EX_PROCESS:      readExtendedProcess(sample); break;
			default: skipTLVRecord(sample, tag, length, "flow_sample_element"); break;
			}
			lengthCheck(sample, "flow_sample_element", start, length);
		}
	}
	lengthCheck(sample, "flow_sample", sampleStart, sampleLength);
	
	if ( verbose ) 
		writeFlowLine(sample);
	sentToGraylog(sample);
}

/*_________________---------------------------__________________
	_________________  readCounters_generic     __________________
	-----------------___________________________------------------
*/

static void readCounters_generic(SFSample *sample)
{
	/* the first part of the generic counters block is really just more info about the interface. */
	sample->ifCounters.ifIndex = sf_log_next32(sample, "ifIndex");
	sample->ifCounters.ifType = sf_log_next32(sample, "networkType");
	sample->ifCounters.ifSpeed = sf_log_next64(sample, "ifSpeed");
	sample->ifCounters.ifDirection = sf_log_next32(sample, "ifDirection");
	sample->ifCounters.ifStatus = sf_log_next32(sample, "ifStatus");
	/* the generic counters always come first */
	sample->ifCounters.ifInOctets = sf_log_next64(sample, "ifInOctets");
	sample->ifCounters.ifInUcastPkts = sf_log_next32(sample, "ifInUcastPkts");
	sample->ifCounters.ifInMulticastPkts = sf_log_next32(sample, "ifInMulticastPkts");
	sample->ifCounters.ifInBroadcastPkts = sf_log_next32(sample, "ifInBroadcastPkts");
	sample->ifCounters.ifInDiscards = sf_log_next32(sample, "ifInDiscards");
	sample->ifCounters.ifInErrors = sf_log_next32(sample, "ifInErrors");
	sample->ifCounters.ifInUnknownProtos = sf_log_next32(sample, "ifInUnknownProtos");
	sample->ifCounters.ifOutOctets = sf_log_next64(sample, "ifOutOctets");
	sample->ifCounters.ifOutUcastPkts = sf_log_next32(sample, "ifOutUcastPkts");
	sample->ifCounters.ifOutMulticastPkts = sf_log_next32(sample, "ifOutMulticastPkts");
	sample->ifCounters.ifOutBroadcastPkts = sf_log_next32(sample, "ifOutBroadcastPkts");
	sample->ifCounters.ifOutDiscards = sf_log_next32(sample, "ifOutDiscards");
	sample->ifCounters.ifOutErrors = sf_log_next32(sample, "ifOutErrors");
	sample->ifCounters.ifPromiscuousMode = sf_log_next32(sample, "ifPromiscuousMode");
}
 
/*_________________---------------------------__________________
	_________________  readCounters_ethernet    __________________
	-----------------___________________________------------------
*/

static  void readCounters_ethernet(SFSample *sample)
{
	sf_log_next32(sample, "dot3StatsAlignmentErrors");
	sf_log_next32(sample, "dot3StatsFCSErrors");
	sf_log_next32(sample, "dot3StatsSingleCollisionFrames");
	sf_log_next32(sample, "dot3StatsMultipleCollisionFrames");
	sf_log_next32(sample, "dot3StatsSQETestErrors");
	sf_log_next32(sample, "dot3StatsDeferredTransmissions");
	sf_log_next32(sample, "dot3StatsLateCollisions");
	sf_log_next32(sample, "dot3StatsExcessiveCollisions");
	sf_log_next32(sample, "dot3StatsInternalMacTransmitErrors");
	sf_log_next32(sample, "dot3StatsCarrierSenseErrors");
	sf_log_next32(sample, "dot3StatsFrameTooLongs");
	sf_log_next32(sample, "dot3StatsInternalMacReceiveErrors");
	sf_log_next32(sample, "dot3StatsSymbolErrors");
}	  

 
/*_________________---------------------------__________________
	_________________  readCounters_tokenring   __________________
	-----------------___________________________------------------
*/

static void readCounters_tokenring(SFSample *sample)
{
	sf_log_next32(sample, "dot5StatsLineErrors");
	sf_log_next32(sample, "dot5StatsBurstErrors");
	sf_log_next32(sample, "dot5StatsACErrors");
	sf_log_next32(sample, "dot5StatsAbortTransErrors");
	sf_log_next32(sample, "dot5StatsInternalErrors");
	sf_log_next32(sample, "dot5StatsLostFrameErrors");
	sf_log_next32(sample, "dot5StatsReceiveCongestions");
	sf_log_next32(sample, "dot5StatsFrameCopiedErrors");
	sf_log_next32(sample, "dot5StatsTokenErrors");
	sf_log_next32(sample, "dot5StatsSoftErrors");
	sf_log_next32(sample, "dot5StatsHardErrors");
	sf_log_next32(sample, "dot5StatsSignalLoss");
	sf_log_next32(sample, "dot5StatsTransmitBeacons");
	sf_log_next32(sample, "dot5StatsRecoverys");
	sf_log_next32(sample, "dot5StatsLobeWires");
	sf_log_next32(sample, "dot5StatsRemoves");
	sf_log_next32(sample, "dot5StatsSingles");
	sf_log_next32(sample, "dot5StatsFreqErrors");
}

 
/*_________________---------------------------__________________
	_________________  readCounters_vg          __________________
	-----------------___________________________------------------
*/

static void readCounters_vg(SFSample *sample)
{
	sf_log_next32(sample, "dot12InHighPriorityFrames");
	sf_log_next64(sample, "dot12InHighPriorityOctets");
	sf_log_next32(sample, "dot12InNormPriorityFrames");
	sf_log_next64(sample, "dot12InNormPriorityOctets");
	sf_log_next32(sample, "dot12InIPMErrors");
	sf_log_next32(sample, "dot12InOversizeFrameErrors");
	sf_log_next32(sample, "dot12InDataErrors");
	sf_log_next32(sample, "dot12InNullAddressedFrames");
	sf_log_next32(sample, "dot12OutHighPriorityFrames");
	sf_log_next64(sample, "dot12OutHighPriorityOctets");
	sf_log_next32(sample, "dot12TransitionIntoTrainings");
	sf_log_next64(sample, "dot12HCInHighPriorityOctets");
	sf_log_next64(sample, "dot12HCInNormPriorityOctets");
	sf_log_next64(sample, "dot12HCOutHighPriorityOctets");
}


 
/*_________________---------------------------__________________
	_________________  readCounters_vlan        __________________
	-----------------___________________________------------------
*/

static void readCounters_vlan(SFSample *sample)
{
	sample->in_vlan = getData32(sample);
	dbg_printf("in_vlan %u\n", sample->in_vlan);
	sf_log_next64(sample, "octets");
	sf_log_next32(sample, "ucastPkts");
	sf_log_next32(sample, "multicastPkts");
	sf_log_next32(sample, "broadcastPkts");
	sf_log_next32(sample, "discards");
}
 
/*_________________---------------------------__________________
	_________________  readCounters_processor   __________________
	-----------------___________________________------------------
*/

static void readCounters_processor(SFSample *sample)
{
	sf_log_percentage(sample, "5s_cpu");
	sf_log_percentage(sample, "1m_cpu");
	sf_log_percentage(sample, "5m_cpu");
	sf_log_next64(sample, "total_memory_bytes");
	sf_log_next64(sample, "free_memory_bytes");
}

/*_________________---------------------------__________________
	_________________  readCountersSample_v2v4  __________________
	-----------------___________________________------------------
*/

static void readCountersSample_v2v4(SFSample *sample)
{
	dbg_printf("sampleType COUNTERSSAMPLE\n");
	sample->samplesGenerated = getData32(sample);
	dbg_printf("sampleSequenceNo %u\n", sample->samplesGenerated);
	{
		uint32_t samplerId = getData32(sample);
		sample->ds_class = samplerId >> 24;
		sample->ds_index = samplerId & 0x00ffffff;
	}
	dbg_printf("sourceId %u:%u\n", sample->ds_class, sample->ds_index);


	sample->statsSamplingInterval = getData32(sample);
	dbg_printf("statsSamplingInterval %u\n", sample->statsSamplingInterval);
	/* now find out what sort of counter blocks we have here... */
	sample->counterBlockVersion = getData32(sample);
	dbg_printf("counterBlockVersion %u\n", sample->counterBlockVersion);
	
	/* first see if we should read the generic stats */
	switch(sample->counterBlockVersion) {
	case INMCOUNTERSVERSION_GENERIC:
	case INMCOUNTERSVERSION_ETHERNET:
	case INMCOUNTERSVERSION_TOKENRING:
	case INMCOUNTERSVERSION_FDDI:
	case INMCOUNTERSVERSION_VG:
	case INMCOUNTERSVERSION_WAN: readCounters_generic(sample); break;
	case INMCOUNTERSVERSION_VLAN: break;
	//default: receiveError(sample, "unknown stats version", YES); break;
	}
	
	/* now see if there are any specific counter blocks to add */
	switch(sample->counterBlockVersion) {
	case INMCOUNTERSVERSION_GENERIC: /* nothing more */ break;
	case INMCOUNTERSVERSION_ETHERNET: readCounters_ethernet(sample); break;
	case INMCOUNTERSVERSION_TOKENRING:readCounters_tokenring(sample); break;
	case INMCOUNTERSVERSION_FDDI: break;
	case INMCOUNTERSVERSION_VG: readCounters_vg(sample); break;
	case INMCOUNTERSVERSION_WAN: break;
	case INMCOUNTERSVERSION_VLAN: readCounters_vlan(sample); break;
	//default: receiveError(sample, "unknown INMCOUNTERSVERSION", YES); break;
	}
	/* line-by-line output... */
	if ( verbose )
		writeCountersLine(sample);
	sentToGraylog(sample);
}

/*_________________---------------------------__________________
	_________________   readCountersSample      __________________
	-----------------___________________________------------------
*/

static void readCountersSample(SFSample *sample, int expanded) {
	uint32_t sampleLength;
	uint32_t num_elements;
	u_char *sampleStart;
	dbg_printf("sampleType COUNTERSSAMPLE\n");
	sampleLength = getData32(sample);
	sampleStart = (u_char *)sample->datap;
	sample->samplesGenerated = getData32(sample);
	
	dbg_printf("sampleSequenceNo %u\n", sample->samplesGenerated);
	if(expanded) {
		sample->ds_class = getData32(sample);
		sample->ds_index = getData32(sample);
	}
	else {
		uint32_t samplerId = getData32(sample);
		sample->ds_class = samplerId >> 24;
		sample->ds_index = samplerId & 0x00ffffff;
	}
	dbg_printf("sourceId %u:%u\n", sample->ds_class, sample->ds_index);
	
	num_elements = getData32(sample);
	{
		int el;
		for(el = 0; el < num_elements; el++) {
#ifdef DEVEL
			char buf[51];
#endif
			uint32_t tag, length;
			u_char *start;
			tag = getData32(sample);
			dbg_printf("counterBlock_tag %s\n", printTag(tag, buf, 50));
			length = getData32(sample);
			start = (u_char *)sample->datap;
			
			switch(tag) {
			case SFLCOUNTERS_GENERIC: readCounters_generic(sample); break;
			case SFLCOUNTERS_ETHERNET: readCounters_ethernet(sample); break;
			case SFLCOUNTERS_TOKENRING:readCounters_tokenring(sample); break;
			case SFLCOUNTERS_VG: readCounters_vg(sample); break;
			case SFLCOUNTERS_VLAN: readCounters_vlan(sample); break;
			case SFLCOUNTERS_PROCESSOR: readCounters_processor(sample); break;
			default: skipTLVRecord(sample, tag, length, "counters_sample_element"); break;
			}
			lengthCheck(sample, "counters_sample_element", start, length);
		}
	}
	lengthCheck(sample, "counters_sample", sampleStart, sampleLength);
	/* line-by-line output... */
	if ( verbose )
		writeCountersLine(sample);
	sentToGraylog(sample);

}

/*_________________---------------------------__________________
	_________________      readSFlowDatagram    __________________
	-----------------___________________________------------------
*/

static inline void readSFlowDatagram(SFSample *sample) {
uint32_t samplesInPacket;
uint32_t samp = 0;
struct timeval now;
#ifdef DEVEL
char buf[51];
#endif

	/* log some datagram info */
	now.tv_sec = time(NULL);
	now.tv_usec = 0;
	dbg_printf("datagramSourceIP %s\n", IP_to_a(sample->sourceIP.s_addr, buf, 51));
	dbg_printf("datagramSize %u\n", sample->rawSampleLen);
	dbg_printf("unixSecondsUTC %llu\n", (unsigned long long)now.tv_sec);

	/* check the version */
	sample->datagramVersion = getData32(sample);
	dbg_printf("datagramVersion %d\n", sample->datagramVersion);
	if(sample->datagramVersion != 2 &&
		 sample->datagramVersion != 4 &&
		 sample->datagramVersion != 5) {
		//receiveError(sample,	"unexpected datagram version number\n", YES);
	}
	
	/* get the agent address */
	getAddress(sample, &sample->agent_addr);

	/* version 5 has an agent sub-id as well */
	if(sample->datagramVersion >= 5) {
		sample->agentSubId = getData32(sample);
		dbg_printf("agentSubId %u\n", sample->agentSubId);
	}

	sample->sequenceNo = getData32(sample);	/* this is the packet sequence number */
	sample->sysUpTime = getData32(sample);
	samplesInPacket = getData32(sample);
	dbg_printf("agent %s\n", printAddress(&sample->agent_addr, buf, 50));
	dbg_printf("packetSequenceNo %u\n", sample->sequenceNo);
	dbg_printf("sysUpTime %u\n", sample->sysUpTime);
	dbg_printf("samplesInPacket %u\n", samplesInPacket);

	/* now iterate and pull out the flows and counters samples */
	for(; samp < samplesInPacket; samp++) {
		memset(&sample->packet_data_tag, 0,
			sizeof(*sample) - ((void *)&sample->packet_data_tag - (void *)sample));

		// just read the tag, then call the approriate decode fn
		sample->sampleType = getData32(sample);
		dbg_printf("startSample ----------------------\n");
		dbg_printf("sampleType_tag %s\n", printTag(sample->sampleType, buf, 50));
		if(sample->datagramVersion >= 5) {
			switch(sample->sampleType) {
				case SFLFLOW_SAMPLE: readFlowSample(sample, NO); 
					break;
				case SFLCOUNTERS_SAMPLE: readCountersSample(sample, NO); 
					break;
				case SFLFLOW_SAMPLE_EXPANDED: readFlowSample(sample, YES); 
					break;
				case SFLCOUNTERS_SAMPLE_EXPANDED: readCountersSample(sample, YES); 
					break;
				default: skipTLVRecord(sample, sample->sampleType, getData32(sample), "sample"); 
					break;
			}
		} else {
			switch(sample->sampleType) {
				case FLOWSAMPLE: readFlowSample_v2v4(sample); 
					break;
				case COUNTERSSAMPLE: readCountersSample_v2v4(sample); 
					break;
				//default: receiveError(sample, "unexpected sample type", YES); 
				//	break;
			}
		}
		dbg_printf("endSample	 ----------------------\n");
	}
} // readSFlowDatagram

void help() {
	printf("\n     --------------\n     -----Help-----\n     --------------\n");
	printf("\nThis program allows you to convert sflow logs comming from a source port of your computer into raw text lines which are sent to a destination port of the same machine. So, it's possible to add sflow logs into Graylog by selecting the Raw/Plaintext UDP input and listening the destination port configured in the sflow-adapter program.\n");
	printf("\nAviable option : \n");
	printf("	-s [port] source port\n");
	printf("	-d [port] destnation port\n");
	printf("	-a [ip address] destination address\n");
	printf("	-h display the help");
	printf("	-l display raw logs\n");
	printf("	-p fork to create another process\n");
	printf("\nUsage exemple : ./sflow-adapter -s 8000 -d 8010 -a 172.20.194.223 -l\n\n");
}

void daemonize() {
	pid_t pid, sid;
	pid = fork();
	if (pid < 0) {
		perror("ERROR: fork");
		exit(1);
	} else if (pid > 0) {
		exit(0);
	}

	umask(0);
	sid = setsid();
	if (sid < 0 ) {
		perror("ERROR: daemonize::sid");
		exit(1);
	}
	
	close( STDIN_FILENO );
	close( STDOUT_FILENO );
	close( STDERR_FILENO );
}


int main (int argc,char *argv[]) {

	/* Options */
	int opt;
	int optl = 0;		//Display raw logs in the terminal
	int optp = 0;		//Create a daemon
	int opta = 0;
	int ports = -1;		//Source port
	int portd = -1;		//Destination port

	char * ipaddress;

	while ((opt = getopt(argc, argv, "ls:d:pa:h")) != -1) {
		switch (opt) {
		case 'l':
			//printf("option l\n");
			optl = 1;
			break;
		case 'p':
			//printf("option p\n");
			optp = 1;
			break;
		case 's': 
			// Source port
			ports = atoi(optarg);
			if (ports <= 1024) {
				perror("ERROR: wrong source port\n");
				exit(1);
			}
			//printf("source port = %d\n", ports);
			break;
		case 'd': 
			// Destination port
			portd = atoi(optarg);
			if (portd <= 1024) {
				perror("ERROR: wrong destination port\n");
				exit(1);
			}
			//printf("destination port = %d\n", portd);
			break;
		case 'a': 
			// Destination address
			opta = 1;
			ipaddress = optarg;
			printf("%s\n", ipaddress);
			break;
		case 'h':
			// help
			help();
			exit(0);
			break;
		}
	} 

	if (ports == -1)  {
		perror("ERROR: the program needs a source port : ./sflow -s [sourceport] -d [destinationport] -a [destination address]\n");
		exit(1);
	} else if (portd == -1) {
		perror("ERROR: the program needs a destination port : ./sflow -s [sourceport] -d [destinationport] -a [destination address]\n");
		exit(1);
	} else if (opta == 0) {
		perror("ERROR: the program needs a destination address : ./sflow -s [sourceport] -d [destinationport] -a [destination address]\n");
		exit(1);
	}

	verbose = optl;


	int sockfd;
	int n;
	struct sockaddr_in  ecoute_addr;
	char recvbuff[3000];
	socklen_t len=sizeof(ecoute_addr);

	/* Let's create a listening socket */
	if ((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("ERROR : socket\n");
		exit(1);
	}

	/* Bind it to the source port */
	memset( (char*) &ecoute_addr,0, sizeof(ecoute_addr) );
	ecoute_addr.sin_family = PF_INET;
	ecoute_addr.sin_addr.s_addr = htonl (INADDR_ANY);
	ecoute_addr.sin_port = htons(ports); //listening port
 
	if (bind(sockfd,(struct sockaddr *)&ecoute_addr, sizeof(ecoute_addr) ) <0) {
		perror ("ERROR : bind\n");
		exit (1);
	}

	/* We create the sending socket */
	if ((sockfdEnvoie = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("ERROR : sending socket\n");
		exit(1);
	}

	/* Destination address */
	memset( (char*) &envoie_addr,0, sizeof(envoie_addr) );
	envoie_addr.sin_family = PF_INET;
	//envoie_addr.sin_addr.s_addr = inet_addr("172.20.194.105");
	envoie_addr.sin_addr.s_addr = inet_addr(ipaddress);
	envoie_addr.sin_port = htons(portd); //destination port

	if (optp) {
		daemonize();
	}

	while(1) {

		n = recvfrom(sockfd, recvbuff, sizeof(recvbuff)-1, 0, (struct sockaddr *)&ecoute_addr, &len);
		if (n <= 0) {
			perror ("ERROR : recvfrom");
			exit(1);
		}
		//recvbuff[n]='\0';
		//printf("Reçu : %d\n", n);

		SFSample sample;
		memset(&sample, 0, sizeof(sample));
		sample.rawSample = recvbuff;
		sample.rawSampleLen = n;

		sample.datap = (uint32_t *)sample.rawSample;
		sample.endp = (u_char *)sample.rawSample + sample.rawSampleLen;
		readSFlowDatagram(&sample);
	

	}

	exit(0);

}


