
#ifndef _PCAP_AXELLIO_H_
#define _PCAP_AXELLIO_H_

pcap_t *pcap_axellio_create(const char *, char *, int *);
int pcap_axellio_findalldevs(pcap_if_list_t *devlistp, char *errbuf);

#define AX_SHM_KEY 0xFA57DA7A

#define cmpxchg(ptr, oldv, newv)  __sync_val_compare_and_swap(ptr, oldv, newv)

inline static void AX_LOCK( volatile int * lock )
{
    while (cmpxchg(lock, 0, 1) != 0 )
    {
        while (*lock != 0) {}; // Spin w/o interlocks...
    }
}

inline static void AX_UNLOCK( volatile int * lock )
{
    *lock = 0;
    //__atomic_store_n( lock, 0, __ATOMIC_SEQ_CST );
}

#define SIZE_OF_DATA_HDR    4   //Each data portion has a header
#define SHM_RING_BUF_SIZE ((64*1024)-SIZE_OF_DATA_HDR) //Size of each ring buffer
#define SHM_RING_SIZE       256 //How many buffers in each ring
#define NUM_RINGS           32  //How many rings

//Data portion of ring structure
typedef struct ax_shmring_data
{
    struct shmring_data_header
    {
        int length;
    } header;

    //Keep the size of the ring
    unsigned char buf[SHM_RING_BUF_SIZE];
} ax_shmring_data_t;

//Metadata structure associated with each ring
typedef struct ax_shm_ring_meta
{
    u_int64_t   put;                //8 Bytes
    u_int64_t   put_packet_cnt;     //16 Bytes
    u_int32_t   put_seg_offset;     //20 Bytes
    u_int32_t   get_unused;         //24 Bytes filler for first cache line
    u_int64_t   get_unused2[5];     //64 Bytes filler filler
    //Separate the get and put sections into separate cachelines
    u_int64_t   get;                //8 Bytes New cacheline
    u_int64_t   get_packet_cnt;     //16 Bytes
    u_int32_t   get_seg_offset;     //20 Bytes
    u_int32_t   state;              //24 Bytes
    u_int64_t   unused[5];          //64 Bytes, filler for second cacheline
} ax_ring_shm_ring_meta_t;

//Rings holding the pcap frames
//Keeping the size of each ring to an even number of cachelines
typedef struct ax_shm_ring
{
    ax_ring_shm_ring_meta_t meta;
    ax_shmring_data_t       data[SHM_RING_SIZE];
}ax_shm_ring_t;

//Shared memory space to hold the rings
typedef struct ax_ring_shmem
{
    u_int32_t           magic;      // 4 Bytes
    u_int32_t           version;    // 8 Bytes
    volatile int32_t    lock;       // 12 Bytes
    u_int8_t            num_rings;  // 13 Bytes
    u_int8_t            ref_count;  // 14 Bytes
    u_int16_t           filler;     // 16 Bytes
    u_int64_t           unused[6];  // 64 Bytes
    //Start the rings on an even cacheline
    //32 rings
    //each ring has 256/SHM_RING_SIZE data entries
    //each data entry is 64KB
    ax_shm_ring_t       ring[NUM_RINGS];
} ax_shmem_t;

typedef struct ax_pfring_priv
{
    unsigned long  rcv_packets;
    unsigned long  dropped_packets;
    ax_shm_ring_t *shmem_ring;
    unsigned int   seg_offset;
    ax_shmem_t    *shmem;
//  etf_table_t   *shmem_etf;
//  pcap_etf_table_t *etf;
//  int lastprintRcv;
//  char filename[128];
} ax_pfring_priv_t;

typedef struct ax_pcap_pkthdr {
    u_int32_t ts_sec;   /* time stamp -Secondd */
    u_int32_t ts_usec;  /* time stamp - microseconds*/
    u_int32_t caplen;   /* length of portion present */
    u_int32_t len;      /* length this packet (off wire) */
}ax_pcap_pkthdr_t;

//int  pfring_mod_axellio_open(pfring *ring);
//void pfring_mod_axellio_close(pfring *ring);
//int  pfring_mod_axellio_stats(pfring *ring, pfring_stat *stats);
//int  pfring_mod_axellio_recv(pfring *ring, u_char** buffer, u_int buffer_len,
//                             struct pfring_pkthdr *hdr,
//                             u_int8_t wait_for_incoming_packet);
//int  pfring_mod_axellio_poll(pfring *ring, u_int wait_duration);
//int  pfring_mod_axellio_enable_ring(pfring *ring);
//int  pfring_mod_axellio_stats(pfring *ring, pfring_stat *stats);
//int  pfring_mod_axellio_set_socket_mode(pfring *ring, socket_mode mode);
//int  pfring_mod_axellio_set_poll_watermark(pfring *ring, u_int16_t watermark);
//int  pfring_mod_axellio_set_bpf_filter(pfring *ring, char *filter_buffer);

#endif /* _PCAP_AXELLIO_H_ */

