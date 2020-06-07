
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/time.h>

#include "pcap-int.h"
#include "pcap-axellio.h"

#define DPDK_PREFIX "dpdk:"

//this struct is our stateful information passed to us by pcap
struct pcap_axellio{
	pcap_t * orig;
	uint16_t portid; // portid of DPDK
	//int must_clear_promisc;
	//uint64_t bpf_drop;
	int nonblock;
	//struct timeval required_select_timeout;
	//struct timeval prev_ts;
	//struct rte_eth_stats prev_stats;
	//struct timeval curr_ts;
	//struct rte_eth_stats curr_stats;
	//uint64_t pps;
	//uint64_t bps;
	//struct rte_mempool * pktmbuf_pool;
	//struct dpdk_ts_helper ts_helper;
	//ETHER_ADDR_TYPE eth_addr;
	//char mac_addr[DPDK_MAC_ADDR_SIZE];
	//char pci_addr[DPDK_PCI_ADDR_SIZE];
	//unsigned char pcap_tmp_buf[RTE_ETH_PCAP_SNAPLEN];
};
#if 0
static int dpdk_read_with_timeout(pcap_t *p, struct rte_mbuf **pkts_burst, const uint16_t burst_cnt){
	struct pcap_dpdk *pd = (struct pcap_dpdk*)(p->priv);
	int nb_rx = 0;
	int timeout_ms = p->opt.timeout;
	int sleep_ms = 0;
	if (pd->nonblock){
		// In non-blocking mode, just read once, no matter how many packets are captured.
		nb_rx = (int)rte_eth_rx_burst(pd->portid, 0, pkts_burst, burst_cnt);
	}else{
		// In blocking mode, read many times until packets are captured or timeout or break_loop is setted.
		// if timeout_ms == 0, it may be blocked forever.
		while (timeout_ms == 0 || sleep_ms < timeout_ms){
			nb_rx = (int)rte_eth_rx_burst(pd->portid, 0, pkts_burst, burst_cnt);
			if (nb_rx){ // got packets within timeout_ms
				break;
			}else{ // no packet arrives at this round.
				if (p->break_loop){
					break;
				}
				// sleep for a very short while.
				// block sleep is the only choice, since usleep() will impact performance dramatically.
				rte_delay_us_block(DPDK_DEF_MIN_SLEEP_MS*1000);
				sleep_ms += DPDK_DEF_MIN_SLEEP_MS;
			}
		}
	}
	return nb_rx;
}

static void nic_stats_display(struct pcap_dpdk *pd)
{
	uint16_t portid = pd->portid;
	struct rte_eth_stats stats;
	rte_eth_stats_get(portid, &stats);
	RTE_LOG(INFO,USER1, "portid:%d, RX-packets: %-10"PRIu64"  RX-errors:  %-10"PRIu64
	       "  RX-bytes:  %-10"PRIu64"  RX-Imissed:  %-10"PRIu64"\n", portid, stats.ipackets, stats.ierrors,
	       stats.ibytes,stats.imissed);
	RTE_LOG(INFO,USER1, "portid:%d, RX-PPS: %-10"PRIu64" RX-Mbps: %.2lf\n", portid, pd->pps, pd->bps/1e6f );
}


static void eth_addr_str(ETHER_ADDR_TYPE *addrp, char* mac_str, int len)
{
	int offset=0;
	if (addrp == NULL){
		snprintf(mac_str, len-1, DPDK_DEF_MAC_ADDR);
		return;
	}
	for (int i=0; i<6; i++)
	{
		if (offset >= len)
		{ // buffer overflow
			return;
		}
		if (i==0)
		{
			snprintf(mac_str+offset, len-1-offset, "%02X",addrp->addr_bytes[i]);
			offset+=2; // FF
		}else{
			snprintf(mac_str+offset, len-1-offset, ":%02X", addrp->addr_bytes[i]);
			offset+=3; // :FF
		}
	}
	return;
}
#endif

static u_char dummypacket[1500] = 
{
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, //Ether Dst
    0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, //Ether Src
    0x80, 0x00, //Ether IP 
    0x45, 0x00, //IPV4, 5 words
    0x05, 0xCE, //total len = 1500-14
    0x01, 0x11, //ID
    0x00, 0x00, //frag/offset
    0x12, 0x11, //TTL, UDP
    0xaa, 0x55, //checksum==bad
    0xc0, 0xa8, 0x53, 0x10, //src IP
    0xc0, 0xa8, 0x54, 0x11, //dst IP
    0x12, 0x34, //UDP src port
    0x43, 0x21, //UDP dst port
    0x05, 0xba, //length
    0x00, 0x00, //checksum
    0x01, 0x02, 0x03, 0x04  //payload
};

static int pcap_axellio_read(pcap_t *p, int max_cnt, pcap_handler cb, u_char *cb_arg)
{
	struct pcap_axellio *pa = (struct pcap_axellio*)(p->priv);
	int pkt_cnt = 0;
	struct pcap_pkthdr pcap_header;
    int i;
    unsigned int pkt_len;    //raj should be 32-bit unsigned
    u_char *bp;

	while(PACKET_COUNT_IS_UNLIMITED(max_cnt) || pkt_cnt < max_cnt)
    {
		if (p->break_loop)
        {
			p->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
#if 0
		// read once in non-blocking mode, or try many times waiting for timeout_ms.
		// if timeout_ms == 0, it will be blocked until one packet arrives or break_loop is set.
		nb_rx = dpdk_read_with_timeout(p, pkts_burst, burst_cnt);
		if (nb_rx == 0)
        {
			if (pd->nonblock)
            {
				RTE_LOG(DEBUG, USER1, "dpdk: no packets available in non-blocking mode.\n");
			}
            else
            {
				if (p->break_loop)
                {
					//_LOG("no packets available and break_loop is set in blocking mode.\n");
					p->break_loop = 0;
					return PCAP_ERROR_BREAK;
				}
				//_LOG("no packets available for timeout %d ms in blocking mode.\n", timeout_ms);
			}
			// break if read 0 packet, no matter in blocking(timeout) or non-blocking mode.
			break;
		}
#endif
		for (i = 0; i < 1; i++) 
        {
            pkt_cnt++;
			pkt_len = 1500;
			pcap_header.caplen = pkt_len < p->snapshot ? pkt_len : p->snapshot;
			pcap_header.len = pkt_len;
			bp = &dummypacket[0]; //pointer to received packet from ring
			if ((p->fcode.bf_insns == NULL) || 
                (bpf_filter(p->fcode.bf_insns, bp, pcap_header.len, pcap_header.caplen)))
            {
				cb(cb_arg, &pcap_header, bp);
			}
            //else
            //{
			//    pd->bpf_drop++;
			//}
		}
	}
	return pkt_cnt;
}
static int pcap_axellio_inject(struct pcap *p, const void *buf _U_, size_t size _U_)
{
	//not implemented yet
	pcap_strlcpy(p->errbuf,
	    "axellio error: Inject function has not been implemented yet",
	    PCAP_ERRBUF_SIZE);
	return PCAP_ERROR;
}

static int pcap_axellio_setnonblock(pcap_t *p, int nonblock)
{
	struct pcap_axellio *pa = (struct pcap_axellio*)(p->priv);
	pa->nonblock = nonblock;
	return 0;
}

static int pcap_axellio_getnonblock(pcap_t *p)
{
	struct pcap_axellio *pa = (struct pcap_axellio*)(p->priv);
	return pa->nonblock;
}

static int pcap_axellio_stats(pcap_t *p, struct pcap_stat *ps)
{
	//struct pcap_axellio *pa = p->priv;
	if (ps)
    {
		ps->ps_recv += 1;
		ps->ps_drop = 0;
		ps->ps_ifdrop = 0;
	}
	return 0;
}

static void pcap_axellio_close(pcap_t *p)
{
	struct pcap_axellio *pa = p->priv;
	if (pa==NULL)
	{
		return;
	}
    //perform any close operations opposite activate
	pcap_cleanup_live_common(p);
}

//this code is called to setup pcap_axellio for each port defined
static int pcap_axellio_activate(pcap_t *p)
{
	struct pcap_axellio *pa = p->priv;
	pa->orig = p;
	int ret = PCAP_ERROR;
	//return PCAP_ERROR_NO_SUCH_DEVICE;
	p->fd = 7;  //??raj 
    if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
    {
        p->snapshot = MAXIMUM_SNAPLEN;
    }
	p->linktype = DLT_EN10MB; // Ethernet, the 10MB is historical.
	p->selectable_fd = p->fd;
	p->read_op = pcap_axellio_read;
	p->inject_op = pcap_axellio_inject;
	p->setfilter_op = install_bpf_program; //pcap filter as we don't have one
	p->setdirection_op = NULL;
	p->set_datalink_op = NULL;
	p->getnonblock_op = pcap_axellio_getnonblock;
	p->setnonblock_op = pcap_axellio_setnonblock;
	p->stats_op = pcap_axellio_stats;
	p->cleanup_op = pcap_axellio_close;
#if 0
	p->breakloop_op = pcap_breakloop_common;
	// set default timeout
	pa->required_select_timeout.tv_sec = 0;
	pa->required_select_timeout.tv_usec = DPDK_DEF_MIN_SLEEP_MS*1000;
	p->required_select_timeout = &pa->required_select_timeout;
#endif
	ret = 0; // OK
	if (ret <= PCAP_ERROR) // all kinds of error code
	{
		pcap_cleanup_live_common(p);
	}
	return ret;
}

// device name for axellio shoud be in the form as axellio:number, such as axellio:0
pcap_t * pcap_axellio_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p=NULL;
	*is_ours = 0;

	*is_ours = !strncmp(device, "axellio:", 8);
	if (! *is_ours)
		return NULL;
	//memset will happen
	p = pcap_create_common(ebuf, sizeof(struct pcap_axellio));

	if (p == NULL)
		return NULL;
	p->activate_op = pcap_axellio_activate;
	return p;
}

int pcap_axellio_findalldevs(pcap_if_list_t *devlistp, char *ebuf)
{
	int ret;
    char name[64];
    char desc[64];

    // this code is where we would go find our shared memory via some mechanism
    // return 0 if we find it, PCAP_ERROR if we don't
    ret = 0;
    snprintf(&name[0], sizeof(name), "axellio:0");
    snprintf(&desc[0], sizeof(desc), "axellio interface axellio0 MAC:xx");
    if (add_dev(devlistp, &name[0], 0, &desc[0], ebuf) == NULL)
    {
        ret = PCAP_ERROR;
    }
	return ret;
}

