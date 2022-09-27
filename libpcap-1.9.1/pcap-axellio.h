#ifndef _PCAP_AXELLIO_H_
#define _PCAP_AXELLIO_H_

#include "axrecvRingSharedMem.h"

pcap_t * pcap_axellio_create( const char *PDeviceName,
                              char *PErrorBuf,
                              int *PIsOurs );
int pcap_axellio_findalldevs( pcap_if_list_t *PDevList,
                              char *PErrorBuf );

/**
 * This is the structure of the PCAP header as we will receive it from the
 * shared memory ring buffers.
 */
struct ax_pcap_pkthdr
{
    uint32_t ts_sec;        /* timestamp seconds */
    uint32_t ts_usec;       /* timestamp microseconds */
    uint32_t incl_len;      /* number of octets of packet saved in file */
    uint32_t orig_len;      /* actual length of packet */
};

#endif /* _PCAP_AXELLIO_H_ */

