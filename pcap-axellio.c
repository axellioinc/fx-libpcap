
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>     //strncmp
#include <unistd.h>     //usleep
#include <time.h>       //clock_gettime
#include <grp.h>        //getgrnam_r

#include "pcap-int.h"
#include "pcap-axellio.h"

#define UNTESTED()  fprintf(stderr, "UNTESTED %s:%d\n", __FILE__, __LINE__);

/**
 * This is our stateful information passed to us by pcap
 */
struct AxPriv
{
    /**
     * During configuration, our shared memory pointer to the ring buffer is
     * setup here.
     */
    struct axrecvRing *PRing;

    /**
     * Our default is to be in blocking mode (NonBlock = 0). Pcap can request
     * that we go into non-blocking mode.
     */
    int NonBlock;

    /**
     * These are statistics for the stats() routine.
     */
    u_int PacketsRx;
    u_int PacketsDropped;
    u_int PacketsIfDropped;

    /**
     * This is the pointer to the shared memory that we will need to shmdt()
     * upon exit.
     */
    void *PShm;
};

/* raj - I'd like to put the getMonotonicOffset(), updateGid(), and
 * openSharedMem() routines into a shared file I could use for PFRing and
 * libpcap code. But for now its copies.
 */

/**
 * This will return a nanosecond counter that always increments and doesn't ever
 * track backwards. This is useful to watch time go by even if NTP happens to
 * reset the wall clock.
 *
 * @return Nanoseconds counter
 */
static int64_t getMonotonicOffset()
{
    struct timespec ts;

    (void)clock_gettime( CLOCK_MONOTONIC, &ts );
    return( (ts.tv_sec * 1000000000LL) + ts.tv_nsec );
}

/**
 * This will wait for there to be something to 'get'. It will timeout if there
 * is nothing to get.
 *
 * @param PPcap - This is needed for the 'break_loop' and we use it to get
 *              access to the ring buffer as well.
 * @param TimeoutNs - When <= 0, there is no timeout and this will wait forever.
 *                  When == 1, there is no waiting, this will just do the quick
 *                  check and return, otherwise the timeout is defined in
 *                  nanoseconds and this will wait up to that amount of time
 *                  while checking for data to be available.
 *
 * @return 0 - Timedout or 'break_loop' and nothing available, 1 - Data is
 *         available on the ring
 */
static int ax_get_wait( pcap_t *PPcap, int64_t TimeoutNs )
{
    struct axrecvRing *pRing;
    int64_t now;
    int64_t expire;
    int dataAvail;

    /* This is an internal routine and we already verified PPcap->priv is not
     * NULL.
     */
    pRing = ((struct AxPriv *)PPcap->priv)->PRing;
    dataAvail = 1;
    if (pRing->Put == pRing->Get)
    {
        //pRing->GetState = 3;
        now = -1;
        expire = 0;
        if (TimeoutNs > 1)
        {
            now = getMonotonicOffset();
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
        while ((pRing->Put == pRing->Get) &&
               (now < expire) &&
               (!PPcap->break_loop))
        {
            usleep( 100 );
            now = getMonotonicOffset();
        }

        /* To get here we either expired the timeout or we have data on the
         * queue.
         */
        if (pRing->Put == pRing->Get)
        {
            dataAvail = 0;
        }
        //pRing->GetState = 1;
    }
    return( dataAvail );
}

/**
 * This routine is called by the libpcap to read some number of packets. Each
 * packet is read from the shared memory and passed to libpcap via the PCb
 * callback if the BPF filter passes the frame.
 *
 * @param PPcap - The libpcap data structure for this instance.
 * @param MaxNumPackets - Can be set to a value to exit after 'n' packets or to
 *                      run forever. When using tcpdump -c n, I saw this set to
 *                      n.
 * @param PCb - When a packet passes the filter, a callback is made to this
 *            function.
 * @param PCbArg - The argument for the callback.
 *
 * @return Number of packets processed.
 */
static int ax_read( pcap_t *PPcap,
                    int MaxNumPackets,
                    pcap_handler PCb,
                    u_char *PCbArg )
{
    struct AxPriv *pAx;
    struct axrecvRing *pRing;
    int totalPackets;
    int64_t timeoutNs;
    struct axrecvRingBuf *pData;
    struct ax_pcap_pkthdr *pAxPcapHdr;
    uint8_t *pPacket;
    uint32_t spaceLeft;
    uint32_t pktLen;
    struct pcap_pkthdr pcapHdr;

    /* Loop until we timeout or return a maximum defined number of packets */
    pAx = (struct AxPriv *)PPcap->priv;
    if (unlikely(pAx == NULL))
    {
        UNTESTED();
        return( -1 );
    }
    pRing = pAx->PRing;
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

    while ((PACKET_COUNT_IS_UNLIMITED(MaxNumPackets)) ||
           (totalPackets < MaxNumPackets))
    {
        /* The pcap library will set this flag to stop us */
        if (unlikely(PPcap->break_loop))
        {
            PPcap->break_loop = 0;
            return( PCAP_ERROR_BREAK );
        }

        /* Try to read data from the ring. The timeoutNs is already setup for
         * blocking and non blocking modes.
         */
        if (ax_get_wait( PPcap, timeoutNs ) == 0)
        {
#ifdef _DEBUG
            if (pAx->NonBlock)
            {
                //no packets available in non blocking mode
                UNTESTED();
            }
#endif  /* _DEBUG */
            break;
        }

        /* Get and Put don't wrap, they just keep incrementing. We need to
         * limit our usage to the actual size of the ring/e.g. data[] but all
         * other tests can use get < put indicating data is available.
         */
        if (pRing->Get < pRing->Put)
        {
            pAx->PacketsRx++;
            pData = &pRing->Data[ pRing->Get % AXRECV_NUM_BUFFERS ];
            pAxPcapHdr =
                (struct ax_pcap_pkthdr *)&pData->Buf[ pRing->GetSegmentOffset ];
            spaceLeft = pData->Length - pRing->GetSegmentOffset;
            if (unlikely(
                (pRing->GetSegmentOffset > pData->Length) ||
                (spaceLeft < sizeof(*pAxPcapHdr)) ||
                (spaceLeft < (sizeof(*pAxPcapHdr) + pAxPcapHdr->incl_len)))
                )
            {
                /* Something is wrong with the data in this segment, let's
                 * skip the data and the remainder of the segment.
                 */
                UNTESTED();
                pRing->GetSegmentOffset = 0;
                pRing->Get++;
                cl_flush( &pRing->Get );
                pAx->PacketsIfDropped++;
                continue;
            }

            /* We now know the memory for the packet header and its length are
             * valid.
             */
            pktLen = pAxPcapHdr->incl_len;
            if (unlikely(pktLen > PPcap->snapshot))
            {
                /* I've seen this when the data flow from the shared memory
                 * queue was bad but not otherwise.
                 */
                pktLen = PPcap->snapshot;
            }

            pcapHdr.ts.tv_sec = pAxPcapHdr->ts_sec;
            pcapHdr.ts.tv_usec = pAxPcapHdr->ts_usec;
            pcapHdr.caplen = pktLen;
            pcapHdr.len = pAxPcapHdr->orig_len;
#ifdef _DEBUG
            UNTESTED();
            if (PPcap->fcode.bf_insns == NULL)
            {
                UNTESTED();
            }
#endif
            pPacket = (uint8_t *)&pAxPcapHdr[1];
            if (bpf_filter(PPcap->fcode.bf_insns,
                           pPacket,
                           pcapHdr.len,
                           pcapHdr.caplen))
            {
                PCb( PCbArg, &pcapHdr, pPacket );
            }
            else
            {
                pAx->PacketsDropped++;
            }

            /* Consume the packet from the ring now that we are done with it */
            totalPackets++;
            pRing->GetPacketCount++;
            pRing->GetSegmentOffset +=
                sizeof(*pAxPcapHdr) + pAxPcapHdr->incl_len;
            if (pRing->GetSegmentOffset >= pData->Length)
            {
                pRing->GetSegmentOffset = 0;
                pRing->Get++;
                cl_flush( &pRing->Get );
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
static int ax_inject( struct pcap *PPcap,
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
static int ax_setnonblock( pcap_t *PPcap, int NonBlock )
{
    struct AxPriv *pAx;

    UNTESTED();
    pAx = (struct AxPriv *)PPcap->priv;
    if (unlikely(pAx == NULL))
    {
        UNTESTED();
        return( -1 );
    }
    pAx->NonBlock = NonBlock;
    return( 0 );
}

static int ax_getnonblock( pcap_t *PPcap )
{
    struct AxPriv *pAx;

    UNTESTED();
    pAx = (struct AxPriv *)PPcap->priv;
    if (unlikely(pAx == NULL))
    {
        UNTESTED();
        return( -1 );
    }
    return( pAx->NonBlock );
}

static int ax_stats( pcap_t *PPcap, struct pcap_stat *PStat )
{
    struct AxPriv *pAx;

    pAx = (struct AxPriv *)PPcap->priv;
    if (unlikely((PStat == NULL) || (pAx == NULL)))
    {
        UNTESTED();
        return( -1 );
    }
    PStat->ps_recv = pAx->PacketsRx;
    PStat->ps_drop = pAx->PacketsDropped;
    PStat->ps_ifdrop = pAx->PacketsIfDropped;
    return( 0 );
}

/**
 * This is called when the user of libpcap is done. This should cleanup the
 * private data.
 *
 * @param PPcap - This is the PCAP data structure that also contains our private
 *              data.
 */
static void ax_close( pcap_t *PPcap )
{
    struct AxPriv *pAx;

    pAx = (struct AxPriv *)PPcap->priv;
    if (likely(pAx != NULL))
    {
        //pAx->PRing->GetState = 0;
        (void)shmdt( pAx->PShm );
        pAx->PShm = NULL;

        /* After this, pAx is no longer valid */
        pcap_cleanup_live_common( PPcap );
        pAx = NULL;
    }
}

static void updateGid( int ShmId, const char *PGroupName )
{
    struct shmid_ds ctrl;
    int stat;
    char *pNameBuf;
    size_t nameBufSize;
    struct group groupData;
    struct group *pGroupResult;

    /* Get the current settings */
    stat = shmctl( ShmId, IPC_STAT, &ctrl );
    if (stat < 0)
    {
        UNTESTED();
        //AXLOGTHROW(m_LogIdError, "UpdateGid() unable to check the current GID");
        return;
    }

    /* Create some memory to return the strings in and attempt to get the group
     * ID data we need. stat will be zero and pGroupResult will be non-NULL if
     * we found the group data.
     */
    nameBufSize = 4*1024;
    pNameBuf = (char *)malloc( nameBufSize );
    pGroupResult = NULL;
    stat = getgrnam_r( PGroupName, &groupData, pNameBuf, nameBufSize,
                       &pGroupResult );
    if ((stat != 0) || (pGroupResult == NULL))
    {
        /* Unable to find group, leave the shared memory group alone */
        //AXLOG(m_LogIdWarn,
        //      "Unable to find group '%s'; "
        //      "shared memory created with groupId=%d",
        //      PGroupName,
        //      ctrl.shm_perm.gid);
    }
    else if (ctrl.shm_perm.gid != pGroupResult->gr_gid)
    {
        /* IPC_SET allows us to change shm_perm.uid, shm_perm.gid, and (the
         * least significant 9 bits of) shm_perm.mode.
         */
        ctrl.shm_perm.gid = pGroupResult->gr_gid;
        stat = shmctl( ShmId, IPC_SET, &ctrl );
#if 0
        if (stat < 0)
        {
            UNTESTED();
            AXLOG(m_LogIdWarn,
                  "Unable to change group id for shared memory; "
                  "shared memory created with groupId=%d",
                  ctrl.shm_perm.gid);
        }
        else
        {
            AXLOG(m_LogIdState, "Shared memory gid changed to %d",
                  ctrl.shm_perm.gid);
        }
#endif
    }
    free( pNameBuf );
}

/**
 *
 *
 *
 * @param PPShm - Returns the handle used to free the shared memory.
 * @param PPAllRings - Returns the handle to the ring buffers.
 */
static void openSharedMem( void **PPShm, struct axrecvAllRings **PPAllRings )
{
    struct AxSharedMemHeader_v1 *pShm;
    int shmId;
    size_t shmSize;
    int needInit;
    int64_t retryUntil;

    pShm = NULL;
    shmSize = sizeof(struct AxSharedMemHeader_v1) +
              sizeof(struct axrecvAllRings);
    retryUntil = getMonotonicOffset() + (250LL * 1000000LL);
    do
    {
        needInit = 0;
        do
        {
            /* Try to create the shared memory in exclusive mode. This will fail
             * if the memory is already created.
             */
            shmId = shmget( AXRECV_RING_KEY,
                            shmSize,
                            IPC_CREAT | IPC_EXCL |
                                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP
                            );
            if (shmId >= 0)
            {
                needInit = 1;
                break;
            }

            /* We had an error creating the shared memory. If the memory already
             * exists then we can just attach to it and we don't need to
             * initialize it at all.
             */
            if (errno == EEXIST)
            {
                shmId = shmget( AXRECV_RING_KEY,
                                shmSize,
                                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );
                if (shmId >= 0)
                {
                    needInit = 0;
                    break;
                }
            }

            /* EACCES is a permission issue. We do want to keep retrying because
             * the permission might be being granted while we are trying.
             */
            UNTESTED();
            usleep( 1 * 1000 );     /* 1ms */
        } while ((shmId < 0) && (getMonotonicOffset() < retryUntil));

        /* If the shared memory was found then attach it */
        if (shmId >= 0)
        {
            pShm = (struct AxSharedMemHeader_v1 *)shmat( shmId, NULL, 0 );
            if ((void *)pShm == (void *)-1)
            {
                UNTESTED();
                //AXLOG(m_LogIdWarn, "Unable to map shared memory=%d/'%s'",
                //      errno, strerror(errno));
                pShm = NULL;
                continue;
            }

            if (needInit)
            {
                /* When shared memory is created, the memory is set to zero.
                 * Initialize the memory and set the magic value last.
                 */
                pShm->HeaderVersion = AX_SHARED_MEM_LATEST_VERSION;
                __atomic_store_n( &pShm->Magic,
                                  AX_SHARED_MEM_MAGIC,
                                  __ATOMIC_SEQ_CST );
            }
            else
            {
                /* The shared memory was already existing. Wait until the magic
                 * is set (in case it was just created and not yet initialized).
                 */
                while ((__atomic_load_n(&pShm->Magic, __ATOMIC_SEQ_CST) !=
                        AX_SHARED_MEM_MAGIC) &&
                       (getMonotonicOffset() < retryUntil))
                {
                    UNTESTED();
                    usleep( 1 * 1000 );     /* 1ms */
                }

                if (unlikely(__atomic_load_n(&pShm->Magic, __ATOMIC_SEQ_CST) !=
                             AX_SHARED_MEM_MAGIC))
                {
                    /* The magic value isn't being set in a reasonable timeframe
                     * so let's assume this isn't our memory. There is no reason
                     * to retry any more because we got our shared memory region
                     * but the memory looks wrong, just give up.
                     */
                    UNTESTED();
                    (void)shmdt( pShm );
                    pShm = NULL;
                    //AXLOGTHROW(m_LogIdError,
                    //           "Magic value is incorrect for shared memory "
                    //           "with key %08xh",
                    //           Key);
                    break;
                }

                switch (pShm->HeaderVersion)
                {
                case AX_SHARED_MEM_LATEST_VERSION:
                    /* For now we only support one version */
                    break;

                default:
                    {
                        UNTESTED();
                        (void)shmdt( pShm );
                        pShm = NULL;
                        //AXLOGTHROW(m_LogIdError,
                        //           "Unknown shared memory version=%u, "
                        //           "expecting version 1",
                        //           version);
                    }
                    break;
                }
            }
            break;
        }
        UNTESTED();
        shmId = -1;
        pShm = NULL;
    } while ((pShm == NULL) && (getMonotonicOffset() < retryUntil));

    if (pShm == NULL)
    {
        UNTESTED();
        *PPShm = NULL;
        *PPAllRings = NULL;
    }
    else
    {
        unsigned ringIndex;
        struct axrecvRing *pRing;
        struct axrecvAllRings *pAllRings;

        pAllRings = (struct axrecvAllRings *)&pShm[1];
        if (needInit)
        {
            /* If we need to initialize then we need to make sure the group is
             * setup the way we want.
             */
            updateGid( shmId, "apcnoperators" );

            pShm->DataVersion = AXRECV_RING_DATA_VERSION;

            for (ringIndex = 0, pRing = &pAllRings->Ring[0];
                 ringIndex < sizeof(pAllRings->Ring)/sizeof(pAllRings->Ring[0]);
                 ringIndex++, pRing++)
            {
                pAllRings->Ring[ringIndex].Put = 0;
                pAllRings->Ring[ringIndex].PutPacketCount = 0;

                pAllRings->Ring[ringIndex].Get = 0;
                pAllRings->Ring[ringIndex].GetPacketCount = 0;
                pAllRings->Ring[ringIndex].GetState = 0;
            }
        }
        else
        {
            switch (pShm->DataVersion)
            {
            case AXRECV_RING_DATA_VERSION:
                break;

            default:
                /* This is an unknown/unsupported version so bail out */
                {
                    (void)shmdt( pShm );
                    pShm = NULL;
                    pAllRings = NULL;
                    //AXLOGTHROW(m_LogIdError,
                    //           "Unknown axrecvRingSharedMem data version=%u",
                    //           version);
                }
                break;
            }
        }

        *PPShm = pShm;
        *PPAllRings = pAllRings;
    }
}

/**
 * After the ax_create() routine is called, this routine is called to active the
 * individual device. We need to error check the actual device number as it
 * corresponds to the shared memory ring and establish all of the shared memory
 * connections.
 *
 * @param PPcap - This is the PCAP data structure that also contains our private
 *              data.
 * @return This is 0 for no error, or PCAP_ERROR or similar.
 */
static int ax_activate( pcap_t *PPcap )
{
    struct AxPriv *pAx;
    void *pShm;
    struct axrecvAllRings *pAllRings;
    unsigned long devId;
    char *pEnd;

    /* Start to setup our private data structure */
    pAx = (struct AxPriv *)PPcap->priv;
    openSharedMem( &pShm, &pAllRings );
    if (pShm == NULL)
    {
        pcap_cleanup_live_common( PPcap );
        return( PCAP_ERROR );
    }

    /* Figure out which ring the user wants us to access */
    devId = strtoul( &PPcap->opt.device[8], &pEnd, 10 );
    if ((pEnd == &PPcap->opt.device[8]) || (*pEnd != '\0') ||
        (devId >= sizeof(pAllRings->Ring)/sizeof(pAllRings->Ring[0])))
    {
        snprintf(PPcap->errbuf, PCAP_ERRBUF_SIZE,
                 "axellio error: ring buffer ID is invalid. device '%s'. "
                 "Valid range is 0..31.",
                 PPcap->opt.device);

        (void)shmdt( pShm );
        pcap_cleanup_live_common( PPcap );
        return( PCAP_ERROR_NO_SUCH_DEVICE );
    }

    /* We have validated devId so we can now setup our internal state */
    pAx->PShm = pShm;
    pAx->PRing = &pAllRings->Ring[ devId ];
    //pAx->SegOffset = 0;
    //pAx->PRing->GetState = 1;   //mark in use

    pAx->NonBlock = 0;
    pAx->PacketsRx = 0;
    pAx->PacketsDropped = 0;
    pAx->PacketsIfDropped = 0;

    /* Setup our overrides for the pcap structure */
    PPcap->read_op = ax_read;
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
    PPcap->inject_op = ax_inject;
    //PPcap->save_current_filter_op
    /* Use the libpcap filter routines as we don't have our own */
    PPcap->setfilter_op = install_bpf_program;
    PPcap->setdirection_op = NULL;
    PPcap->set_datalink_op = NULL;
    PPcap->getnonblock_op = ax_getnonblock;
    PPcap->setnonblock_op = ax_setnonblock;
    PPcap->stats_op = ax_stats;
    //PPcap->oneshot_callback
    PPcap->cleanup_op = ax_close;
    return( 0 );
}

/**
 * This routine is called to create the pcap data structure that will contain
 * our private data fields. In addition we setup the routine callback that will
 * fill in that structure. We are expecting the device name to be 'axellio:%u'.
 * This routine is attached to a list in pcap.c so that we can be called to
 * identify our own device.
 *
 * @param PDeviceName - The name supplied by the user. This needs to be
 *                    validated that it starts with 'axellio:'
 * @param PErrorBuf - Location to return an error string if there was an error.
 * @param PIsOurs - Used to return true if this is our device, false if not.
 */
pcap_t * pcap_axellio_create( const char *PDeviceName,
                              char *PErrorBuf,
                              int *PIsOurs )
{
    pcap_t *pPcap;

    /* Make sure the device is our expected type. We do get calls for other
     * system devices and just need to reject those. It seems the pcap code just
     * walks a list and calls create for all of them. At this point we only
     * verify that the prefix of the name is what we expect, there is no range
     * check on the device number or even to see if it exists. That will happen
     * in the activate routine.
     */
    *PIsOurs = !strncmp(PDeviceName, "axellio:", 8);
    if (!(*PIsOurs))
    {
        return( NULL );
    }

    /* Create the pcap data structure with enough space for our private data */
    pPcap = pcap_create_common( PErrorBuf, sizeof(struct AxPriv) );
    if (pPcap == NULL)
    {
        UNTESTED();
        return( NULL );
    }

    /* We only need to fill in the activate_op callback for now */
    pPcap->activate_op = ax_activate;
    return( pPcap );
}

/**
 * This routine is not always called to find the devices present. Our
 * implementation will always find all possible axellio rings because if the
 * shared memory is not present then we will create it. tcpdump -D will call
 * this routine.
 *
 * @param PDevList - Used to return devices found
 * @param PErrorBuf - Used to return an error string if any
 * @return PCAP_ERROR or 0 for no error
 */
int pcap_axellio_findalldevs( pcap_if_list_t *PDevList, char *PErrorBuf )
{
    void *pShm;
    struct axrecvAllRings *pAllRings;
    unsigned ringIndex;
    char name[64];
    char desc[64];

    openSharedMem( &pShm, &pAllRings );
    if (pShm == NULL)
    {
        UNTESTED();
        return( 0 );
    }

    (void)shmdt( pShm );
    pShm = NULL;
    pAllRings = NULL;
    for (ringIndex = 0;
         ringIndex < sizeof(pAllRings->Ring)/sizeof(pAllRings->Ring[0]);
         ringIndex++)
    {
        snprintf(&name[0], sizeof(name), "axellio:%u", ringIndex);
        snprintf(&desc[0], sizeof(desc),
                 "Axellio shared memory ring %u", ringIndex);
        if (add_dev(PDevList, &name[0], 0, &desc[0], PErrorBuf) == NULL)
        {
            UNTESTED();
            return( PCAP_ERROR );
        }
    }
    return( 0 );
}

