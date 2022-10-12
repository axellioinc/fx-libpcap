#ifndef _axrecvRingSharedMem_h_
#define _axrecvRingSharedMem_h_

#include "axStdDefs.h"
#include "axSharedMem.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#define AXSHM_PERMS (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IWOTH|S_IROTH)
#define MAX_NUM_RINGSETS 16
#define RINGSET_OWNER_CMDLINE_MAX_LENGTH 2048
#define AXRECV_SHMKEY 0xFA57DA7A

// This defines the ring directory that lives in the well-known shared memory.
struct axrecvRingDirectory {
    int num_ringsets;
    struct ringset_direntry {
        char owner_commandline[RINGSET_OWNER_CMDLINE_MAX_LENGTH];
        int owner_pid;
        uint64_t owner_last_seen_time;
    } ringsets[MAX_NUM_RINGSETS];
};

// This defines the number of rings we will allocate memory space for.
// A provider of this ring data (axrecv) will only populate data for some number
// of rings 0..NUM_RINGS. Because the shared memory might be created by a
// monitor (axrecvmon) or consumer program (pfring or libpcap), we can't really
// check at the time of creation by those programs how many rings are being
// provided. So at this time, we just allow all of the rings data to be
// monitored at any time.
#define AXRECV_NUM_RINGS            32

// This defines the number of buffers within a ring.
#define AXRECV_NUM_BUFFERS          256

// This defines the size in bytes of a single ring buffer. Each ring buffer will
// contain some number of pcap packets (network packets). This buffer must be
// able to handle a full network packet (max ~10KB from Napatech). It also must
// not be so large as to introduce too much latency nor so small as to introduce
// too much transaction overhead.
#define AXRECV_BUFFER_SIZE          (64 * 1024)

// The axSharedMem class allows us to set a 32-bit version to identify our data
// structure for possible future changes. This is that version.
#define AXRECV_RING_DATA_VERSION    2

// This is a single data buffer within the ring. Each buffer is expected to be
// an integral multiple of the cache line size.
struct axrecvRingBuf {
    // Each buffer can vary in length. Each buffer will contain an integral
    // multiple of pcap packets with pcap headers as well. Length will be at
    // minimum the pcap header size and at maximum sizeof(Buf).
    uint32_t Length;

    // This is the buffer to store the pcap packets in. Our goal is to keep the
    // sizeof this data structure exactly AXRECV_BUFFER_SIZE to keep things
    // aligned nicely on cache lines.
    uint8_t Buf[ AXRECV_BUFFER_SIZE - sizeof(uint32_t) ];
};

// This defines a single ring buffer. The total size of this is meant to be a
// multiple of the cache line size.
struct axrecvRing {
    // Put is the monotonically incrementing buffer index that will next have
    // data put into it. i.e. Data[Put] is the producer's next location. When
    // the producer is done filling the buffer, then they increment Put. To
    // index Data[], you must use a modulo operation such as Data[Put %
    // AXRECV_NUM_BUFFERS].
    volatile uint64_t Put;

    // This counts the number of packets in the buffers that have been put.
    volatile uint64_t PutPackets;

    // This counts the number of times a put buffer has been flushed due to a
    // timeout after some data was put into the buffer but before the buffer was
    // full.
    volatile uint64_t PutFlushes;

    // All of the Get data is on the next cache line

    // Get is the monotonically incrementing buffer index that needs to be read
    // next. If Get==Put then the buffer is not ready. To index Data[], you must
    // use a modulo operation such as Data[Get % AXRECV_NUM_BUFFERS].
    volatile uint64_t Get __attribute((aligned(64)));

    // This counts the number of packets in the buffers that have been read.
    volatile uint64_t GetPackets;

    // This can be used for debugging or understanding the state of the 'get'
    // thread such as libpcap. It isn't used anywhere else and is not marked
    // volatile because of that.
    uint64_t GetState;

    // Because programs like tcpdump might read a partial segment, we need to
    // keep a current segment offset state variable. This is not considered
    // volatile because it should only be read/written by the 'get' thread.
    uint64_t GetSegmentOffset;

    // This is the actual ring data buffer set and they start on the next cache
    // line.
    struct axrecvRingBuf Data[AXRECV_NUM_BUFFERS]
        __attribute((aligned(64)));
};

// This is the shared memory space to hold the rings themselves. We allocate
// AXRECV_NUM_RINGS. Because ring shared memory might be allocated by the
// consumer, there isn't any way to tell that a ring is currently having data
// produced or not.
struct axrecvAllRings {
    // Now for the rings themselves. Each of these rings is expected to be
    // aligned on a cache line boundary.
    struct axrecvRing Ring[AXRECV_NUM_RINGS];
};

struct recvSharedMemory {
    struct axrecvRingDirectory directory;
    struct axrecvAllRings ringsets[1];
};

struct axrecvSharedMemory {
    struct AxSharedMemHeader_v1 header;
    struct recvSharedMemory recvSharedMemory;
};

struct axrecvSharedMemoryHeader {
    struct AxSharedMemHeader_v1 header;
    struct axrecvRingDirectory directory;
};

#ifdef __cplusplus
}   // End the extern C

// The rest of this is only compiled when in C++ mode. This allows us to share
// the above data structures with libpcap and pfring.
#include "axLogging.h"

// This class defines the ring buffer shared memory for axrecv. This shared
// memory is read by either libpcap or pfring.
class axrecvRingSharedMem {
public:
    // This is the key we use for this shared memory region.
    static const key_t s_Key = AXRECV_SHMKEY;

    // This will report the size of the memory content we need.
    static const size_t s_Size = sizeof(axrecvAllRings);

    // Construct the shared memory class. This does not allocate shared memory,
    // just the resources needed by this class. Call Initialize() after
    // construction.
    //
    // @param LogName - The unique name for this class' logger.
    // @param LogMask - The mask to turn on/off logs for this instance.
    axrecvRingSharedMem( const std::string &LogName, uint64_t LogMask );
    virtual ~axrecvRingSharedMem();
    axrecvRingSharedMem( const axrecvRingSharedMem & ) = delete;
    axrecvRingSharedMem & operator = ( const axrecvRingSharedMem & ) = delete;

    // Initialize the shared memory. This routine will throw if it has any
    // issues mapping the shared memory.
    void Initialize(unsigned ringset, unsigned num_ringsets);

    // This will return a pointer to the specific ring requested.
    //
    // @param RingIndex - Which ring to get access to, value from
    //                  0..AXRECV_NUM_RINGS-1
    // @return Pointer to the ring shared memory or NULL if invalid.
    axrecvRing *PRing( unsigned RingIndex ) {
        if (likely((m_PAllRings != NULL) && (RingIndex < AXRECV_NUM_RINGS))) {
            return( &m_PAllRings->Ring[RingIndex] );
        }
        return( NULL );
    }

    // This routine is used by some debugging tools to dump the shared memory
    // in human readable format.
    void DumpSharedMem();

private:
    axLogInstance *m_PLogger;
    int m_LogIdError;
    int m_LogIdWarn;
    int m_LogIdDebug;

    axSharedMem *m_PSharedMem;
    axrecvAllRings *m_PAllRings;
};

#endif  // __cplusplus
#endif  // _axrecvRingSharedMem_h_

