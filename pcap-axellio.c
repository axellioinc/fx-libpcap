
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
#include <sys/types.h>  //required for shm
#include <sys/ipc.h>    //shm
#include <sys/shm.h>

#include "pcap-int.h"
#include "pcap-axellio.h"

#define UNTESTED()  fprintf(stderr, "UNTESTED %s:%d\n", __FILE__, __LINE__);

//this struct is our stateful information passed to us by pcap
struct pcap_axellio
{
    pcap_t *PPcap;

    ax_shm_ring_t *PRing;
    unsigned int SegOffset;
    ax_shmem_t *PShmem;
    int Shmid;

    int NonBlock;

    u_int PacketsRx;
    u_int PacketsDropped;
    u_int PacketsIfDropped;
    //struct timeval required_select_timeout;
};

/**
 *
 *
 * @param PPcap
 * @param TimeoutNs - When <= 0, there is no timeout and this will wait forever.
 *                  When == 1, there is no waiting, this will just do the quick
 *                  check and return, otherwise the timeout is defined in
 *                  nanoseconds and this will wait up to that amount of time
 *                  while checking for data to be available.
 *
 * @return 0 - Timedout or 'break_loop' and nothing available, 1 - Data is
 *         available on the ring
 */
static int pcap_axellio_get_wait( pcap_t *PPcap, int64_t TimeoutNs )
{
    ax_shm_ring_t *pRing;
    volatile u_int64_t *pPut;
    struct timespec ts;
    int64_t now;
    int64_t expire;

    pRing = ((struct pcap_axellio *)PPcap->priv)->PRing;
    pRing->meta.state = 3;
    pPut = &pRing->meta.put;    //need the volatile or some other construct
    if (*pPut == pRing->meta.get)
    {
        now = -1;
        expire = 0;
        if (TimeoutNs > 1)
        {
            (void)clock_gettime(CLOCK_MONOTONIC, &ts);
            now = ((int64_t)ts.tv_sec * 1000000000LL) +
                  (int64_t)ts.tv_nsec;
            expire = now + TimeoutNs;
        }
        else if (TimeoutNs == 1)
        {
            /* We don't want to loop at all so we reset now to skip the loop
             * below.
             */
            UNTESTED();
            now = expire;
        }

        /* When expire == 0, now == -1 and this will loop until data is ready */
        while ((*pPut == pRing->meta.get) &&
               (now < expire) &&
               (!PPcap->break_loop))
        {
            usleep( 100 );
            if (expire > 0)
            {
                clock_gettime( CLOCK_MONOTONIC, &ts );
                now = ((int64_t)ts.tv_sec * 1000000000LL) +
                      (int64_t)ts.tv_nsec;
            }
            else
            {
                UNTESTED();
            }
        }

        /* To get here we either expired the timeout or we have data on the
         * queue.
         */
        if (*pPut == pRing->meta.get)
        {
            //raj pfring code was leaving the state alone for a timeout return
            //pRing->meta.state = 1;
            return( 0 );
        }
    }
    pRing->meta.state = 1;
    return( 1 );    /* Something is available */
}

static int pcap_axellio_read( pcap_t *PPcap,
                              int MaxNumPackets,
                              pcap_handler PCb,
                              u_char *PCbArg )
{
    struct pcap_pkthdr pcapHdr;
    struct pcap_axellio *pAx;
    ax_shm_ring_t *pRing;
    volatile u_int64_t *pPut;
    volatile u_int64_t *pGet;
    int totalPackets;
    int64_t timeoutNs;
    ax_shmring_data_t *pData;
    unsigned char *pPacket;
    ax_pcap_pkthdr_t *pAxPcapHdr;
    u_int32_t pktLen;

    /* Loop until we timeout or return a maximum defined number of packets */
    pAx = (struct pcap_axellio *)PPcap->priv;
    pRing = pAx->PRing;
    pPut = (volatile u_int64_t *)&pRing->meta.put;
    pGet = (volatile u_int64_t *)&pRing->meta.get;
    totalPackets = 0;

    /* Try to read data from the ring. We have two modes of operation, blocking
     * and non blocking. During initial testing with tcpdump, the mode as
     * blocking with a timeout of 1000ms. A timeout of zero is expected to wait
     * forever. We setup the timeout here and use it through the loop.
     */
    timeoutNs = (int64_t)PPcap->opt.timeout * 1000000LL;
    if (pAx->NonBlock)
    {
        /* For non-blocking we set the timeout to 1ns to get an immediate
         * return, no waiting.
         */
        UNTESTED();
        timeoutNs = 1;
    }

#if 1 //debug
    /* I have only seen MaxNumPackets be 'unlimited' so far */
    if (!PACKET_COUNT_IS_UNLIMITED(MaxNumPackets))
    {
        UNTESTED();
    }
#endif

    while ((PACKET_COUNT_IS_UNLIMITED(MaxNumPackets)) ||
           (totalPackets < MaxNumPackets))
    {
        /* The pcap library will set this flag to stop us */
        if (PPcap->break_loop)
        {
            PPcap->break_loop = 0;
            return( PCAP_ERROR_BREAK );
        }

        /* Try to read data from the ring. The timeoutNs is already setup for
         * blocking and non blocking modes.
         */
        if (pcap_axellio_get_wait( PPcap, timeoutNs ) == 0)
        {
            if (pAx->NonBlock)  //raj debug?
            {
                //no packets available in non blocking mode
                UNTESTED();
            }
            break;
        }

        /* get and put don't wrap, they just keep incrementing. We need to limit
         * our usage to the actual size of the ring/e.g. data[] but all other
         * tests can use get < put indicating data is available.
         */
        if (*pGet < *pPut)
        {
            pData = &pRing->data[ (*pGet) % SHM_RING_SIZE ];
            pPacket = &pData->buf[ pRing->meta.get_seg_offset ];
            pAxPcapHdr = (ax_pcap_pkthdr_t *)pPacket;
            pPacket += sizeof(*pAxPcapHdr);
            pktLen = pAxPcapHdr->caplen;
            if (pktLen > PPcap->snapshot)
            {
                /* I've seen this when the data flow from the shared memory
                 * queue was bad but not otherwise.
                 */
                pktLen = PPcap->snapshot;
            }

            pcapHdr.ts.tv_sec = pAxPcapHdr->ts_sec;
            pcapHdr.ts.tv_usec = pAxPcapHdr->ts_usec;
            pcapHdr.caplen = pktLen;
            pcapHdr.len = pAxPcapHdr->len;
#if 1
            if (PPcap->fcode.bf_insns == NULL)
            {
                UNTESTED();
            }
#endif
            if (bpf_filter(PPcap->fcode.bf_insns,
                           pPacket, pcapHdr.len, pcapHdr.caplen))
            {
                PCb( PCbArg, &pcapHdr, pPacket );
            }
            else
            {
                pAx->PacketsDropped++;
            }

            /* Consume the packet from the ring now that we are done with it */
            totalPackets++;
            pAx->PacketsRx++;

            pRing->meta.get_seg_offset +=
                pAxPcapHdr->caplen + sizeof(*pAxPcapHdr);
            pRing->meta.get_packet_cnt++;
            if (pRing->meta.get_seg_offset >= pData->header.length)
            {
                /* Move to next segment to pick packets from */
                (*pGet)++;
                pRing->meta.get_seg_offset = 0;
            }
        }
    }
    return( totalPackets );
}

/**
 * We currently do not implement the inject function.
 *
 * @param PPcap - This is the PCAP data structure that also contains our private
 *              data.
 * @return int Error status, 0 = no error
 */
static int pcap_axellio_inject( struct pcap *PPcap,
                                const void *PBuf __attribute__((unused)),
                                size_t BufLen __attribute__((unused)) )
{
    UNTESTED();
    snprintf(PPcap->errbuf, PCAP_ERRBUF_SIZE,
             "axellio error: Inject function has not been implemented yet");
    return( PCAP_ERROR );
}

/**
 * This allows the user to set a non-block state of on or off.
 *
 * @param PPcap - This is the PCAP data structure that also contains our private
 *              data.
 * @param NonBlock - 0 = allow block, 1 = do not allow block (non-blocking)
 *
 * @return int Error status, 0 = no error
 */
static int pcap_axellio_setnonblock( pcap_t *PPcap, int NonBlock )
{
    struct pcap_axellio *pAx;

    UNTESTED();
    pAx = (struct pcap_axellio *)PPcap->priv;
    pAx->NonBlock = NonBlock;
    return( 0 );
}

static int pcap_axellio_getnonblock( pcap_t *PPcap )
{
    struct pcap_axellio *pAx;

    UNTESTED();
    pAx = (struct pcap_axellio *)PPcap->priv;
    return( pAx->NonBlock );
}

static int pcap_axellio_stats( pcap_t *PPcap, struct pcap_stat *PStat )
{
    struct pcap_axellio *pAx;

    if (PStat != NULL)
    {
        pAx = (struct pcap_axellio *)PPcap->priv;
        PStat->ps_recv = pAx->PacketsRx;
        PStat->ps_drop = pAx->PacketsDropped;
        PStat->ps_ifdrop = pAx->PacketsIfDropped;
    }
    return 0;
}

/**
 * This is called when the user of libpcap is done. This should cleanup the
 * private data.
 *
 * @param PPcap - This is the PCAP data structure that also contains our private
 *              data.
 */
static void pcap_axellio_close( pcap_t *PPcap )
{
    struct pcap_axellio *pAx;

    pAx = (struct pcap_axellio *)PPcap->priv;
    if (pAx != NULL)
    {
        AX_LOCK( &pAx->PShmem->lock );
        pAx->PShmem->ref_count--;
        pAx->PRing->meta.state = 66;
        AX_UNLOCK( &pAx->PShmem->lock );

        if (shmdt( pAx->PShmem ) != 0)
        {
            UNTESTED();
        }
        pAx->PShmem = NULL;

        /* After this, pAx is no longer valid */
        pcap_cleanup_live_common( PPcap );
        pAx = NULL;
    }
}

/**
 * After the pcap_axellio_create() routine is called, this routine is called to
 * active the individual device. We need to error check the actual device number
 * as it corresponds to the shared memory ring and establish all of the shared
 * memory connections.
 *
 * @param PPcap - This is the PCAP data structure that also contains our private
 *              data.
 * @return int - This is 0 for no error, or PCAP_ERROR or similar.
 */
static int pcap_axellio_activate( pcap_t *PPcap )
{
    struct pcap_axellio *pAx;
    char *pEnd;
    unsigned long devId;
    uint8_t numRings;

    /* Start to setup our private data structure */
    pAx = (struct pcap_axellio *)PPcap->priv;
    pAx->PPcap = PPcap;

    /* If we create the shared memory segment then it will be initialized to
     * zeroes. We really don't want to create the segment because if nothing is
     * providing data to us then we would strand a bunch of memory.
     */
    pAx->Shmid = shmget( AX_SHM_KEY, sizeof(ax_shmem_t), SHM_R | SHM_W );
    if (pAx->Shmid < 0)
    {
        snprintf(PPcap->errbuf, PCAP_ERRBUF_SIZE,
                 "Unable to find AX shared memory region");
        pcap_cleanup_live_common( PPcap );
        return( 0 );
    }

    pAx->PShmem = (ax_shmem_t *)shmat( pAx->Shmid, NULL, SHM_RND );
    if (pAx->PShmem == (ax_shmem_t *)-1)
    {
        UNTESTED();
        snprintf(PPcap->errbuf, PCAP_ERRBUF_SIZE,
                 "Failed to attach shared memory region=%d/%s",
                 errno, strerror(errno));
        pcap_cleanup_live_common( PPcap );
        return( PCAP_ERROR );
    }

    AX_LOCK( &pAx->PShmem->lock );
    numRings = pAx->PShmem->num_rings;
    printf("magic=%08x\n", pAx->PShmem->magic);
    printf("numRings=%u\n", numRings);
    AX_UNLOCK( &pAx->PShmem->lock );

    /* Figure out which ring the user wants us to access */
    devId = strtoul( &PPcap->opt.device[8], &pEnd, 10 );
    if ((pEnd == &PPcap->opt.device[8]) || (*pEnd != '\0') ||
        (devId >= numRings))
    {
        snprintf( PPcap->errbuf, PCAP_ERRBUF_SIZE,
                  "axellio error: ring buffer ID is invalid. device '%s'",
                  PPcap->opt.device);
        pcap_cleanup_live_common( PPcap );
        return( PCAP_ERROR_NO_SUCH_DEVICE );
    }

    /* We have validated devId so we can now setup our internal state */
    AX_LOCK( &pAx->PShmem->lock );
    pAx->PRing = &pAx->PShmem->ring[ devId ];
    pAx->SegOffset = 0;

    /* Mark this ring as being in use */
    pAx->PShmem->ref_count++;
    pAx->PRing->meta.state = 1; //raj?
    AX_UNLOCK( &pAx->PShmem->lock );

    pAx->NonBlock = 0;
    pAx->PacketsRx = 0;
    pAx->PacketsDropped = 0;
    pAx->PacketsIfDropped = 0;

    /* Setup our overrides for the pcap structure */
    PPcap->read_op = pcap_axellio_read;
    //PPcap->next_packet_op = NULL;
    PPcap->fd = -1;
    //PPcap->priv;
    if ((PPcap->snapshot <= 0) || (PPcap->snapshot > MAXIMUM_SNAPLEN))
    {
        UNTESTED();
        PPcap->snapshot = MAXIMUM_SNAPLEN;
    }

    PPcap->linktype = DLT_EN10MB; // Ethernet, the 10MB is historical.

    //raj does this work?
    PPcap->selectable_fd = -1;
    PPcap->required_select_timeout = NULL;
#if 0
    pAx->required_select_timeout.tv_sec = 0;
    pAx->required_select_timeout.tv_usec = DPDK_DEF_MIN_SLEEP_MS*1000;
    PPcap->required_select_timeout = &pAx->required_select_timeout;
#endif

    //PPcap->activate_op        set prev
    //PPcap->can_set_rfmon_op
    PPcap->inject_op = pcap_axellio_inject;
    //PPcap->save_current_filter_op
    /* Use the libpcap filter routines as we don't have our own */
    PPcap->setfilter_op = install_bpf_program;
    PPcap->setdirection_op = NULL;
    PPcap->set_datalink_op = NULL;
    PPcap->getnonblock_op = pcap_axellio_getnonblock;
    PPcap->setnonblock_op = pcap_axellio_setnonblock;
    PPcap->stats_op = pcap_axellio_stats;
    //PPcap->oneshot_callback
    PPcap->cleanup_op = pcap_axellio_close;
    return( 0 );
}

/**
 * This routine is called to create the pcap data structure that will contain
 * our private data fields. In addition we setup the routine callback that will
 * fill in that structure. We are expecting the device name to be 'axellio:%u'.
 * This routine is attached to a list in pcap.c so that we can be called to
 * identify our own device.
 */
pcap_t * pcap_axellio_create( const char *DeviceName,
                              char *ErrorBuf,
                              int *IsOurs )
{
    pcap_t *pPcap;

    /* Make sure the device is our expected type. We do get calls for other
     * system devices and just need to reject those. It seems the pcap code just
     * walks a list and calls create for all of them. At this point we only
     * verify that the prefix of the name is what we expect, there is no range
     * check on the device number or even to see if it exists. That will happen
     * in the activate routine.
     */
    *IsOurs = !strncmp(DeviceName, "axellio:", 8);
    if (!(*IsOurs))
    {
        return( NULL );
    }

    /* Create the pcap data structure with enough space for our private data */
    pPcap = pcap_create_common( ErrorBuf, sizeof(struct pcap_axellio) );
    if (pPcap == NULL)
    {
        UNTESTED();
        return( NULL );
    }

    /* We only need to fill in the activate_op callback for now */
    pPcap->activate_op = pcap_axellio_activate;
    return( pPcap );
}

int pcap_axellio_findalldevs( pcap_if_list_t *devlistp, char *ErrorBuf )
{
    int ret;
    char name[64];
    char desc[64];
    int shmid;
    ax_shmem_t *pShmem;
    uint8_t numRings;
    uint8_t i;

    /* If we create the shared memory segment then it will be initialized to
     * zeroes. We really don't want to create the segment because if nothing is
     * providing data to us then we would strand a bunch of memory.
     */
    shmid = shmget( AX_SHM_KEY, sizeof(ax_shmem_t),
                    /*IPC_CREAT |*/ SHM_R | SHM_W
                    );
    if (shmid < 0)
    {
        snprintf(ErrorBuf, PCAP_ERRBUF_SIZE,
                 "Unable to find AX shared memory region");
        return( 0 );
    }

    pShmem = (ax_shmem_t *)shmat( shmid, NULL, SHM_RND );
    if (pShmem == (ax_shmem_t *)-1)
    {
        UNTESTED();
        snprintf(ErrorBuf, PCAP_ERRBUF_SIZE,
                 "Failed to attach shared memory region=%d/%s",
                 errno, strerror(errno));
        return( PCAP_ERROR );
    }

    AX_LOCK( &pShmem->lock );
    numRings = pShmem->num_rings;
    printf("magic=%08x\n", pShmem->magic);
    printf("numRings=%u\n", numRings);
    AX_UNLOCK( &pShmem->lock );

    if (shmdt( pShmem ) != 0)
    {
        UNTESTED();
        snprintf(ErrorBuf, PCAP_ERRBUF_SIZE,
                 "Failed to detach shared memory region=%d/%s",
                 errno, strerror(errno));
        return( PCAP_ERROR );
    }
    pShmem = NULL;

    ret = 0;
    for (i = 0; i < numRings; i++)
    {
        snprintf(&name[0], sizeof(name), "axellio:%u", i);
        snprintf(&desc[0], sizeof(desc),
                 "Axellio shared memory interface %u", i);
        if (add_dev(devlistp, &name[0], 0, &desc[0], ErrorBuf) == NULL)
        {
            UNTESTED();
            ret = PCAP_ERROR;
            break;
        }
    }
    return( ret );
}

