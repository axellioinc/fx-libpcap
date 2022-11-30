
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>     //strncmp
#include <unistd.h>     //usleep
#include <time.h>       //clock_gettime
#include <grp.h>        //getgrnam_r
#include <fcntl.h>
#include <regex.h>
#include <ctype.h>

#include "pcap-int.h"
#include "pcap-axellio.h"

#define UNTESTED()  fprintf(stderr, "UNTESTED %s:%d\n", __FILE__, __LINE__);

// This is our stateful information passed to us by pcap
struct AxPriv {
    // During configuration, our shared memory pointer to the ring buffer is
    // setup here.
    struct axrecvRing *PRing;

    // Our default is to be in blocking mode (NonBlock = 0). Pcap can request
    // that we go into non-blocking mode.
    int NonBlock;

    // These are statistics for the stats() routine.
    u_int PacketsRx;
    u_int PacketsDropped;
    u_int PacketsIfDropped;

    // This is the pointer to the shared memory that we will need to shmdt()
    // upon exit.
    void *shared_memory;
};

/**
 * This will return a nanosecond counter that always increments and doesn't ever
 * track backwards. This is useful to watch time go by even if NTP happens to
 * reset the wall clock.
 *
 * @return Nanoseconds counter
 */
static int64_t 
getMonotonicOffset() {
    struct timespec ts;

    (void)clock_gettime( CLOCK_MONOTONIC, &ts );
    return( (ts.tv_sec * 1000000000LL) + ts.tv_nsec );
}

struct option {
	struct option *next;
	char name[80];
	char value[300];
};

struct section {
	struct section *next;
	struct option *options;
	char name[80];
};

struct config {
	struct section *sections;
};

char *
trim(char *str) {
	char *end;
	// Trim leading space
	while(isspace((unsigned char)*str)) str++;
	if(*str == 0)  // All spaces?
		return str;
	// Trim trailing space
	end = str + strlen(str) - 1;
	while(end > str && isspace((unsigned char)*end)) end--;
	// Write new null terminator character
	end[1] = '\0';
	return str;
}

struct section *
section_get(char *name, struct config *config, int create) {
	struct section *section=config->sections;
	struct section *last_section=NULL;
	if(name==NULL) name="";
	while(section) {
		if(!strcasecmp(name,section->name)) return section;
		last_section=section;
		section=section->next;
	}
	if(!create) return NULL;
	section=malloc(sizeof(struct section));
	strcpy(section->name,name);
	section->next=NULL;
	section->options=NULL;
	if(last_section) {
		last_section->next=section;
	} else {
		config->sections=section;
	}
	return section;
}

struct option *
option_get(char *name, struct section *section, int create) {
	struct option *option=section->options;
	struct option *last_option=NULL;
	while(option) {
		if(!strcasecmp(name,option->name)) return option;
		last_option=option;
		option=option->next;
	}
	if(!create) return NULL;
	option=malloc(sizeof(struct option));
	strcpy(option->name,name);
	option->next=NULL;
	option->value[0]='\0';
	if(last_option) {
		last_option->next=option;
	} else {
		section->options=option;
	}
	return option;
}

int
config_readfile(char *file, struct config *options) {
	FILE *fp=fopen(file,"r");
	if(!fp) {
		perror("can't open");
		return -errno;
	}
	struct section *section=section_get("",options,1);
	char line[500];
	while(NULL!=fgets(line,500,fp)) {
		char *p=trim(line);
		if(p[0]=='#') { //comment
			continue;
		}
		if(p[0]=='[') { // new section
			char *close_bracket=strchr(&p[1],']');
			if(!close_bracket) { // :(
				fprintf(stderr,"no bracket closure: %s\n",p);
				continue;
			}
			*close_bracket='\0';
			p++;
			section=section_get(p,options,1);
			continue;
		}
		char *equals=strchr(p,'=');
		if(!equals) {
			if(strlen(p))
				fprintf(stderr,"no value defined: %s\n",p);
			continue;
		}
		*equals='\0';
		char *name=trim(p);
		struct option *option=option_get(name,section,1);
		char *value=trim(equals+1);
		strcpy(option->value,value);
	}
	fclose(fp);
	return 0;
}

char *
config_get(char *section_name,char *option_name, struct config *config) {
	struct section *section=section_get(section_name,config,0);
	if(!section) return NULL;
	struct option *option=option_get(option_name,section,0);
	if(!option) return NULL;
	return option->value;
}

// Get the commandline of this application
static char *
command_line_get(void) {
    static char cmdline[RINGSET_OWNER_CMDLINE_MAX_LENGTH];
    char file[256];
    int len,i;
    sprintf(file,"/proc/%d/cmdline",getpid());
    int fd=open(file,O_RDONLY);
    if(fd<0) {
        perror("open cmdline");
        return NULL;
    }
    len=read(fd,cmdline,2047);
    if(len<0) {
        close(fd);
        perror("read cmdline");
        return NULL;
    }
    for(i=0;i<len-1;i++) {
        if(cmdline[i]=='\0') cmdline[i]=' ';
    }
    close(fd);
    return cmdline;
}

static void 
updateGid( int ShmId, const char *PGroupName ) {
    struct shmid_ds ctrl;
    int stat;
    char *pNameBuf;
    size_t nameBufSize;
    struct group groupData;
    struct group *pGroupResult;

    /* Get the current settings */
    stat = shmctl( ShmId, IPC_STAT, &ctrl );
    if (stat < 0) {
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
    if((stat != 0) || (pGroupResult == NULL)) {
        /* Unable to find group, leave the shared memory group alone */
    } else if (ctrl.shm_perm.gid != pGroupResult->gr_gid) {
        /* IPC_SET allows us to change shm_perm.uid, shm_perm.gid, and (the
         * least significant 9 bits of) shm_perm.mode.
         */
        ctrl.shm_perm.gid = pGroupResult->gr_gid;
        stat = shmctl( ShmId, IPC_SET, &ctrl );
    }
    free( pNameBuf );
}

int
ringset_select_pidandname(struct axrecvSharedMemory *shm, int num_ringsets, 
  int64_t deadline, struct config *config) {
    int i,loops=0;
    struct axrecvRingDirectory *dir=&shm->recvSharedMemory.directory;

    // Walk through the directory and see if this process already has a ringset
    char *cmdline=command_line_get();
    int ringset=-1;
    struct ringset_direntry *de;
    for(i=0;i<num_ringsets;i++) {
        de=&dir->ringsets[i];
        if(strncmp(cmdline,de->owner_commandline,
          RINGSET_OWNER_CMDLINE_MAX_LENGTH))
            continue;
        // the name matches, let's hope there's not already an owner!
        if(de->owner_pid) {
            if(de->owner_pid!=getpid()) {
                // maybe it's dead?
                int still_alive=1;
                char path[256];
                sprintf(path,"/proc/%d",de->owner_pid);
                struct stat sb;
                while(0==stat(path,&sb)) {
                    // other process is running, wait here.
                    if(loops%100==0) {
                        fprintf(stderr,
                        "waiting for identically run process %d to exit\n",
                        de->owner_pid);
                        fprintf(stderr,"I am %s[%d], other is %s[%d]\n",cmdline,
                        getpid(),de->owner_commandline,de->owner_pid);
                    }
                    usleep(100 * 1000); // 100ms
                    loops++;
                }
            } else {
                printf("reopening %d from same pid, I am %s[%d]\n",i,
                  cmdline,de->owner_pid);
            }
        }
        return i;
    }

    // If it wasn't there then go through the ringsets and find a good slot or
    // wait for one if there isn't one available
    while(ringset==-1 && (getMonotonicOffset() < deadline)) {
        for(i=0;i<num_ringsets;i++) {
            de=&dir->ringsets[i];
            if(de->owner_last_seen_time==0) {
                return i;
            }
        }

        // Didn't find an empty slot, let's see if there's one to expire
        for(i=0;i<num_ringsets;i++) {
            de=&dir->ringsets[i];
            struct stat sb;
            char path[256];
            // If the process that owns this slot has been gone for 10 minutes
            // then we will presume it is dead.
            sprintf(path,"/proc/%d",de->owner_pid);
            if(stat(path,&sb)) { // it's gone!
                int expiry_time=de->owner_last_seen_time+10*60;
                if(time(NULL)>expiry_time) { // found a victim!
                    fprintf(stderr,"EXPIRING ringset %d owned by %s[%d]\n",i,de->owner_commandline,de->owner_pid);
                    return i;
                }
            }
            fprintf(stderr,"can't steal ringset %d owned by %s[%d]\n",i,de->owner_commandline,de->owner_pid);
        }

        // Didn't find one. Print periodically, and try again after a pause.
        loops++;
        if(loops%100==0) fprintf(stderr,
            "waiting for shared memory ring slot to become available\n");
        usleep(100 * 1000);
    }
    return -1;
}

int
regex_check(char *expression, char *value) {
    regex_t regex;
    int ret;
    // compile the regular expression
    ret=regcomp(&regex,expression,0);
    if(ret!=0) {
        fprintf(stderr,"%s: can't compile regular expression '%s': %s\n",
          __func__,expression,strerror(errno));
        return -1;
    }
    // evaluate the expression
    ret=regexec(&regex,value,0,NULL,0);
    return ret;
}

int
ringset_select_by_regex(struct axrecvSharedMemory *shm, int num_ringsets, 
  int64_t deadline, struct config *config) {
    int ret;
    char *cmdline=command_line_get();
    char option_name[100];
    int ringset;

    for(ringset=0;ringset<num_ringsets;ringset++) {
        sprintf(option_name,"ringset_%d_regex",ringset);
        char *regex=config_get(NULL,option_name,config);
        if(!regex) continue;

        ret=regex_check(regex,cmdline);
        if(ret!=0) continue;
        fprintf(stderr,"%s: matched %s: %s[%d]\n",__func__,regex,cmdline,getpid());
        return ringset;
    }

    return -1;
}

int
ringset_select(struct axrecvSharedMemory *shm, int num_ringsets, 
  int64_t deadline) {
    static struct config *config=NULL;
    if(!config) {
        int ret;
        config=malloc(sizeof(struct config));
        memset(config,0,sizeof(config));
        ret=config_readfile("/opt/axellio/config/fx-libpcap.ini",config);
        ret=config_readfile("/opt/axellio/config/px-libpcap.ini",config);
        // ignore ret....!?!
    }
    int ringset;
    ringset=ringset_select_by_regex(shm,num_ringsets,deadline,config);
    if(ringset!=-1) return ringset;
    ringset=ringset_select_pidandname(shm,num_ringsets,deadline,config);
    return ringset;
}

/**
 * @param Pshared_memory - Returns the handle used to free the shared memory.
 * @param PPAllRings - Returns the handle to the ring buffers.
 */
void * 
openSharedMem( struct AxPriv *priv, struct axrecvAllRings **PPAllRings, 
  int blocking ) {
    struct axrecvSharedMemory *shm=NULL;
    struct AxSharedMemHeader_v1 *header;
    int shmId=-1;
    int64_t retryUntil;
    struct axrecvSharedMemoryHeader *shmheader;
    int num_ringsets=0;

    retryUntil = getMonotonicOffset() + (250LL * 1000000LL);

    // Map the shared memory.
    while((shm == NULL) && (getMonotonicOffset() < retryUntil)) {
        // Try to get the shared memory header region ONLY.
        shmId = shmget( AXRECV_SHMKEY, sizeof(struct axrecvSharedMemoryHeader), 
          AXSHM_PERMS );
        if(shmId<0) {
            usleep( 1 * 1000 );     /* 1ms */
            continue;
        }

        // Now attach to shared memory.
        shmheader = (struct axrecvSharedMemoryHeader *)shmat( shmId, NULL, 0 );
        if ((void *)shmheader == (void *)-1) {
            UNTESTED();
            //AXLOG(m_LogIdWarn, "Unable to map shared memory=%d/'%s'",
            //      errno, strerror(errno));
            shmheader = NULL;
            continue;
        }

        header=&shmheader->header;

        // The shared memory already existed. Wait until the magic
        // is set (in case it was just created and not yet initialized).
        while ((__atomic_load_n(&header->Magic, __ATOMIC_SEQ_CST) !=
            AX_SHARED_MEM_MAGIC) && (getMonotonicOffset() < retryUntil)) {
            UNTESTED();
            usleep( 1 * 1000 );     /* 1ms */
        }

        if (unlikely(__atomic_load_n(&header->Magic, __ATOMIC_SEQ_CST) 
            != AX_SHARED_MEM_MAGIC)) {
            // The magic value isn't being set in a reasonable timeframe
            // so let's assume this isn't our memory. There is no reason
            // to retry any more because we got our shared memory region
            // but the memory looks wrong, just give up.
            UNTESTED();
            (void)shmdt( shmheader );
            shmheader = NULL;
            break;
        }

        switch (header->HeaderVersion)  {
        case AX_SHARED_MEM_LATEST_VERSION:
            /* For now we only support one version */
            break;

        default: 
            UNTESTED();
            (void)shmdt( shmheader );
            shmheader = NULL;
            break;
        }

        switch (header->DataVersion) {
        case AXRECV_RING_DATA_VERSION:
            break;

        default:
            /* This is an unknown/unsupported version so bail out */
            fprintf(stderr,"header->DataVersion %d (expected %d)\n",
            header->DataVersion,AXRECV_RING_DATA_VERSION);
            (void)shmdt( shmheader );
            shmheader = NULL;
            break;
        }

        num_ringsets=shmheader->directory.num_ringsets;
        shmdt(shmheader); // drop the header mapping

        // Great, it's probably OK. Get the full region.
        unsigned long amt=sizeof(struct axrecvSharedMemoryHeader)+
          num_ringsets*sizeof(struct axrecvAllRings);
        shmId = shmget( AXRECV_SHMKEY, amt, AXSHM_PERMS );
        if (shmId<0) {
            usleep( 1 * 1000 );     /* 1ms */
            continue;
        }

        // Now attach to shared memory.
        shm = (struct axrecvSharedMemory *)shmat( shmId, NULL, 0 );
        if((void *)shm == (void *)-1) {
            UNTESTED();
            //AXLOG(m_LogIdWarn, "Unable to map shared memory=%d/'%s'",
            //      errno, strerror(errno));
            shm = NULL;
            continue;
        }
    }

    // Did we time out or something?
    if (shm == NULL) {
        priv->shared_memory = NULL;
        *PPAllRings = NULL;
        fprintf(stderr,"fx-libpcap timeout opening shared memory\n");
        return NULL;
    } 

    // Now figure out which ringset we will use.
    int ringset;
    ringset=ringset_select(shm,num_ringsets,retryUntil);
    if(ringset==-1) { // didn't get one in time!
        shmdt(shm);
        priv->shared_memory=NULL;
        fprintf(stderr,"fxlibpcap timeout getting ringset\n");
        return NULL;
    }

    // We are now the proud owner of ringset
    struct axrecvRingDirectory *dir=&shm->recvSharedMemory.directory;
    struct ringset_direntry *de;
    char *cmdline=command_line_get();
    de=&dir->ringsets[ringset];
    de->owner_pid=getpid();
    de->owner_last_seen_time=time(NULL);
    strncpy(de->owner_commandline,cmdline,RINGSET_OWNER_CMDLINE_MAX_LENGTH);

    *PPAllRings=(struct axrecvAllRings *)&shm->recvSharedMemory.ringsets[ringset];

    return shm;
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
static int 
ax_get_wait( pcap_t *PPcap, int64_t TimeoutNs ) {
    struct axrecvRing *pRing;
    int64_t now;
    int64_t expire;
    int dataAvail;

    // This is an internal routine and we already know PPcap->priv isn't NULL
    pRing = ((struct AxPriv *)PPcap->priv)->PRing;
    dataAvail = 1;
    if (pRing->Put == pRing->Get) {
        //pRing->GetState = 3;
        now = -1;
        expire = 0;
        if (TimeoutNs > 1) {
            now = getMonotonicOffset();
            expire = now + TimeoutNs;
        } else if (TimeoutNs == 1) {
            // We don't want to loop at all so we reset to skip the loop below
            now = expire;
        }

        /* When expire == 0, now == -1 and this will loop until data is ready */
        while((pRing->Put == pRing->Get) && (now < expire) &&
          (!PPcap->break_loop)) {
            usleep( 100 );
            now = getMonotonicOffset();
        }

        // To get here we either expired the timeout or have data on the queue
        if (pRing->Put == pRing->Get) {
            dataAvail = 0;
        }
        //pRing->GetState = 1;
    }
    return( dataAvail );
}

static int
shared_memory_open(pcap_t *pcap, int blocking) {
    unsigned long devid;
    struct AxPriv *priv=(struct AxPriv *)pcap->priv;
    struct axrecvAllRings *rings;
    char *end;

    if(priv->shared_memory) return 0;

    priv->shared_memory=openSharedMem(priv, &rings, blocking);
    if(priv->shared_memory == NULL) {
        pcap_cleanup_live_common( pcap );
        return PCAP_ERROR;
    }

    /* Figure out which ring the user wants us to access */
    devid = strtoul( &pcap->opt.device[8], &end, 10 );
    if ((end == &pcap->opt.device[8]) || (*end != '\0') ||
      (devid >= sizeof(rings->Ring)/sizeof(rings->Ring[0]))) {
        snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
          "axellio error: ring buffer ID is invalid. device '%s'. "
          "Valid range is 0..31.",pcap->opt.device);
        (void)shmdt(priv->shared_memory);
        pcap_cleanup_live_common(pcap);
        return PCAP_ERROR_NO_SUCH_DEVICE;
    }

    /* We have validated devid so we can now setup our internal state */
    priv->PRing = &rings->Ring[devid];

    return 0; // success!
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
static int 
ax_read(pcap_t *PPcap, int MaxNumPackets, pcap_handler PCb,
  u_char *PCbArg) {
    struct AxPriv *pAx=(struct AxPriv *)PPcap->priv;
    struct axrecvRing *pRing;
    int totalPackets;
    int64_t timeoutNs;
    struct axrecvRingBuf *pData;
    struct ax_pcap_pkthdr *pAxPcapHdr;
    uint8_t *pPacket;
    uint32_t spaceLeft;
    uint32_t pktLen;
    struct pcap_pkthdr pcapHdr;

    if (unlikely(pAx == NULL)) {
        UNTESTED();
        return( -1 );
    }

    if(0!=shared_memory_open(PPcap,pAx->NonBlock?0:1)) {
        fprintf(stderr,"%s Unable to open shared memory\n",__func__);
        return 0; // can't open memory, return no data
    }

    /* Loop until we timeout or return a maximum defined number of packets */
    pRing = pAx->PRing;
    totalPackets = 0;

    /* Try to read data from the ring. We have two modes of operation, blocking
     * and non blocking. During initial testing with tcpdump, the mode as
     * blocking with a timeout of 1000ms. A timeout of zero is expected to wait
     * forever. We setup the timeout here and use it through the loop.
     */
    timeoutNs = (int64_t)PPcap->opt.timeout * 1000000LL;
    if (pAx->NonBlock) {
        // For non-blocking we set the timeout to 1ns to get an immediate
        // return, no waiting.
        timeoutNs = 1;
    }

    while ((PACKET_COUNT_IS_UNLIMITED(MaxNumPackets)) ||
      (totalPackets < MaxNumPackets)) {
        /* The pcap library will set this flag to stop us */
        if (unlikely(PPcap->break_loop)) {
            PPcap->break_loop = 0;
            fprintf(stderr,"%s exit PCAP_ERROR_BREAK\n");
            fflush(stderr);
            return( PCAP_ERROR_BREAK );
        }

        // Try to read data from the ring. The timeoutNs is already setup for
        // blocking and non blocking modes.
        if (ax_get_wait( PPcap, timeoutNs ) == 0) {
            break;
        }

        /* Get and Put don't wrap, they just keep incrementing. We need to
         * limit our usage to the actual size of the ring/e.g. data[] but all
         * other tests can use get < put indicating data is available.
         */
        if (pRing->Get < pRing->Put) {
            pAx->PacketsRx++;
            pData = &pRing->Data[ pRing->Get % AXRECV_NUM_BUFFERS ];
            pAxPcapHdr =
              (struct ax_pcap_pkthdr *)&pData->Buf[ pRing->GetSegmentOffset ];
            spaceLeft = pData->Length - pRing->GetSegmentOffset;
            if (unlikely((pRing->GetSegmentOffset > pData->Length) ||
              (spaceLeft < sizeof(*pAxPcapHdr)) ||
              (spaceLeft < (sizeof(*pAxPcapHdr) + pAxPcapHdr->incl_len)))) {
                // Something is wrong with the data in this segment, let's
                // skip the data and the remainder of the segment.
                UNTESTED();
                pRing->GetSegmentOffset = 0;
                pRing->Get++;
                cl_flush( &pRing->Get );
                pAx->PacketsIfDropped++;
                continue;
            }

            // We now know the memory for the packet header and its length are
            // valid.
            pktLen = pAxPcapHdr->incl_len;
            if (unlikely(pktLen > PPcap->snapshot)) {
                // I've seen this when the data flow from the shared memory
                // queue was bad but not otherwise.
                pktLen = PPcap->snapshot;
            }

            pcapHdr.ts.tv_sec = pAxPcapHdr->ts_sec;
            pcapHdr.ts.tv_usec = pAxPcapHdr->ts_usec;
            pcapHdr.caplen = pktLen;
            pcapHdr.len = pAxPcapHdr->orig_len;

            pPacket = (uint8_t *)&pAxPcapHdr[1];
            if (bpf_filter(PPcap->fcode.bf_insns, pPacket, pcapHdr.len,
              pcapHdr.caplen)) {
                PCb( PCbArg, &pcapHdr, pPacket );
            } else {
                pAx->PacketsDropped++;
            }

            /* Consume the packet from the ring now that we are done with it */
            totalPackets++;
            pRing->GetPackets++;
            pRing->GetSegmentOffset+=sizeof(*pAxPcapHdr) + pAxPcapHdr->incl_len;
            if (pRing->GetSegmentOffset >= pData->Length) {
                pRing->GetSegmentOffset = 0;
                pRing->Get++;
                cl_flush( &pRing->Get );
            }
        }
    }
    return totalPackets;
}

/**
 * We currently do not implement the inject function.
 *
 * @param PPcap - This is the PCAP data structure that also contains our private
 *              data.
 * @return int Error status, 0 = no error
 */
static int 
ax_inject(struct pcap *PPcap, 
  const void *PBuf __attribute__((unused)), 
  size_t BufLen __attribute__((unused))) {
    UNTESTED();
    snprintf(PPcap->errbuf, PCAP_ERRBUF_SIZE,
             "axellio error: Inject function has not been implemented yet");
    return PCAP_ERROR;
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
static int 
ax_setnonblock( pcap_t *PPcap, int NonBlock ) {
    struct AxPriv *pAx;

    pAx = (struct AxPriv *)PPcap->priv;
    if (unlikely(pAx == NULL)) {
        UNTESTED();
        return( -1 );
    }
    pAx->NonBlock = NonBlock;
    return 0;
}

static int 
ax_getnonblock( pcap_t *PPcap ) {
    struct AxPriv *pAx;

    UNTESTED();
    pAx = (struct AxPriv *)PPcap->priv;
    if (unlikely(pAx == NULL)) {
        UNTESTED();
        return( -1 );
    }
    return( pAx->NonBlock );
}

static int 
ax_stats( pcap_t *PPcap, struct pcap_stat *PStat ) {
    struct AxPriv *pAx;

    pAx = (struct AxPriv *)PPcap->priv;
    if (unlikely((PStat == NULL) || (pAx == NULL))) {
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
static void 
ax_close( pcap_t *PPcap ) {
    struct AxPriv *pAx;

    pAx = (struct AxPriv *)PPcap->priv;
    if (likely(pAx != NULL)) {
        (void)shmdt( pAx->shared_memory );
        pAx->shared_memory = NULL;
        pAx->PRing=NULL;

        /* After this, pAx is no longer valid */
        pcap_cleanup_live_common( PPcap );
        pAx = NULL;
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
static int 
ax_activate( pcap_t *PPcap ) {
    /* Start to setup our private data structure */
    struct AxPriv *pAx = (struct AxPriv *)PPcap->priv;

    pAx->NonBlock = 0;
    pAx->PacketsRx = 0;
    pAx->PacketsDropped = 0;
    pAx->PacketsIfDropped = 0;

    /* Setup our overrides for the pcap structure */
    PPcap->read_op = ax_read;
    //PPcap->next_packet_op = NULL;
    PPcap->fd = -1;
    //PPcap->priv;
    if ((PPcap->snapshot <= 0) || (PPcap->snapshot > MAXIMUM_SNAPLEN)) {
        PPcap->snapshot = MAXIMUM_SNAPLEN;
    }

    PPcap->linktype = DLT_EN10MB; // Ethernet, the 10MB is historical.

    //raj does this work?
    PPcap->selectable_fd = -1;
    PPcap->required_select_timeout = NULL;

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
pcap_t * 
pcap_axellio_create( const char *PDeviceName, char *PErrorBuf,
  int *PIsOurs ) {
    pcap_t *pPcap;

    // Make sure the device is our expected type. We do get calls for other
    // system devices and just need to reject those. It seems the pcap code just
    // walks a list and calls create for all of them. At this point we only
    // verify that the prefix of the name is what we expect, there is no range
    // check on the device number or even to see if it exists. That will happen
    // in the activate routine.
    *PIsOurs = !strncmp(PDeviceName, "axellio:", 8);
    if (!(*PIsOurs)) {
        return( NULL );
    }

    /* Create the pcap data structure with enough space for our private data */
    pPcap = pcap_create_common( PErrorBuf, sizeof(struct AxPriv) );
    if (pPcap == NULL) {
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
int 
pcap_axellio_findalldevs( pcap_if_list_t *PDevList, char *PErrorBuf ) {
    struct axrecvAllRings *pAllRings;
    unsigned ringIndex;
    char name[64];
    char desc[64];
    struct AxPriv private;

    private.shared_memory=openSharedMem( &private, &pAllRings, 1 );
    if (private.shared_memory == NULL) {
        UNTESTED();
        return( 0 );
    }

    (void)shmdt(private.shared_memory);
    pAllRings = NULL;
    for (ringIndex = 0;
      ringIndex < sizeof(pAllRings->Ring)/sizeof(pAllRings->Ring[0]);
      ringIndex++) {
        snprintf(&name[0], sizeof(name), "axellio:%u", ringIndex);
        snprintf(&desc[0], sizeof(desc),
          "Axellio shared memory ring %u", ringIndex);
        if (add_dev(PDevList, &name[0], 0, &desc[0], PErrorBuf) == NULL) {
            UNTESTED();
            return( PCAP_ERROR );
        }
    }
    return( 0 );
}

