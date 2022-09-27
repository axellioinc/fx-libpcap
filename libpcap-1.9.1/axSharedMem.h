#ifndef _axSharedMem_h_
#define _axSharedMem_h_

#include <sys/shm.h>    //shmget...
#include <sys/stat.h>   //S_IRUSR...
#include "axStdDefs.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

/**
 * The magic value is 'AXIO'
 */
#define AX_SHARED_MEM_MAGIC             0x4158494F

/**
 * This is the most recent version for shared memory. All memory created by
 * this instance will be created using this version.
 */
#define AX_SHARED_MEM_LATEST_VERSION    1

/**
 * All shared memory regions will prepend this structure to the space to be
 * allocated. The pointer returned by GetSharedMem() returns a pointer to this
 * structure. The memory immediately following this structure is the size of
 * 'Size' from the call to Open().
 *
 * Because allocating shared memory starts on page boundaries, this structure is
 * expected to start on a page boundary. When I laid out the data for the
 * structure I assumed that the entire version 1 structure would fit in the same
 * cache line at the very least.
 */
struct AxSharedMemHeader_v1
{
    /**
     * The magic value is set to indicate that this memory is known to this
     * code. We set the value to AX_SHARED_MEM_MAGIC.
     */
    uint32_t Magic;

    /**
     * The version of this header. This header is version 1.
     */
    uint32_t HeaderVersion;

    /**
     * The version of the data following this header. This value is setup,
     * tested, managed by the code using this class. The default value will be
     * zero.
     */
    uint32_t DataVersion;

    /**
     * PFRing needs a place to allocate users of rings. The current usage
     * for zeek has multiple processes vying for different rings. The only way
     * to manage that is via a shared location. To obtain a ring number, take
     * the lock, then find the lowest bit position in the RingInUseMask and
     * allocate a ring using the index of that bit position. e.g. if
     * RingInUseMask is 0x7, then or in bit (1<<3)==0x8 and use ring 3. When
     * exiting, make sure to clear the bit for the ring you had allocated.
     */
    volatile uint32_t Lock;
    uint32_t RingInUseMask;

    /**
     * Reserved space for future usage and to pad the data out to a cache line
     * size.
     */
    uint8_t Reserved[ 64 - (sizeof(uint32_t) * 5) ];

} __attribute__((packed));

/**
 * This can be used to lock the AxSharedMemHeader_v1 Lock
 *
 * @param PLock - Pointer to AxSharedMemHeader_v1::Lock
 */
inline static void AX_SHM_LOCK( volatile uint32_t *PLock )
{
    while (cmpxchg(PLock, 0, 1) != 0)
    {
        while (*PLock != 0);    // Spin w/o interlocks...
    }
}

/**
 * This can be used to unlock the AxSharedMemHeader_v1 Lock
 *
 * @param PLock - Pointer to AxSharedMemHeader_v1::Lock
 */
inline static void AX_SHM_UNLOCK( volatile uint32_t *PLock )
{
    __atomic_store_n( PLock, 0, __ATOMIC_SEQ_CST );
}

#ifdef __cplusplus
}   /* End the extern C */

/* The rest of this is only compiled when in C++ mode. This allows us to share
 * the above data structures with libpcap and pfring.
 */
#include "axLogging.h"

/**
 * This class can be used to manage shared memory in a standard manner for
 * Axellio applications. All shared memory managed by this class has a common
 * header that can be used to validate that the memory region is being used by
 * an Axellio application.
 *
 * If the shared memory exists then the class will validate it before allowing
 * Open() to succeed. If the shared memory does not exist then Open() creates it
 * and adds the appropriate header information so that other applications can
 * validate the memory region.
 */
class axSharedMem
{
public:
    /**
     * Construct the shared memory class. This does not allocate shared memory,
     * just the resources needed by this class.
     *
     * @param PLogName - The unique name for this class' logger.
     * @param LogMask - The mask to turn on/off logs for this instance.
     */
    axSharedMem( const char *PLogName, uint64_t LogMask );
    virtual ~axSharedMem();
    axSharedMem( const axSharedMem & ) = delete;
    axSharedMem & operator = ( const axSharedMem & ) = delete;

    /**
     * Attempt to open/create the shared memory using the arguments given. If
     * the memory was created then this returns true and the caller should
     * initialize the memory following the header. Otherwise the shared memory
     * region was already present and has been validated. Obtain a pointer to
     * the region using GetSharedMem().
     *
     * @param Key - The key for shmget()
     * @param Size - The size of the shared memory to create/obtain. A header of
     *             sizeof(AxSharedMemHeader_v1) is added to this memory size.
     * @param ModeFlags - The lower 9-bits of flags for shmget(). e.g. S_IRUSR,
     *                  S_IRGRP, S_IROTH
     * @return true - the shared memory region was created, false - the shared
     *         memory region already existed and is validated.
     */
    bool Open( key_t Key,
               size_t Size,
               int ModeFlags );

    /**
     * Close the opened shared memory. After calling this, the pointer returned
     * by GetSharedMem() is no longer valid.
     */
    void Close();

    /**
     * Update the group ID of the shared memory to the given group name.
     *
     * @param PGroupName - The name of the group to change the gid to.
     */
    void UpdateGid( const char *PGroupName );

    /**
     * Get a pointer to the shared memory region starting at the common header
     * (AxSharedMemHeader_v1). Returns NULL if none has been created/obtained
     * yet. This pointer is only valid until Close() is called. The pointer
     * returned refers to the AxSharedMemHeader_v1 header. The user's shared
     * memory immediately follows this header.
     */
    void *GetSharedMemHeader()
    {
        return( m_PShm );
    }

    /**
     * Get a pointer to the users shared memory region. Returns NULL if none has
     * been created/obtained yet. This pointer is only valid until Close() is
     * called. The pointer returned refers to the first byte following the
     * AxSharedMemHeader_v1 header.
     */
    void *GetSharedMem()
    {
        return( (uint8_t *)m_PShm + sizeof(AxSharedMemHeader_v1) );
    }

    /**
     * All headers since version 1 have a header version that is handled by this
     * class and a data version handled by the user of this class. The user can
     * set the data version with this routine.
     *
     * @param Version - The version value to set
     */
    void SetDataVersion( uint32_t Version );

    /**
     * All headers since version 1 have a header version that is handled by this
     * class and a data version handled by the user of this class. The user can
     * get the data version with this routine.
     *
     * @return - The version value
     */
    uint32_t GetDataVersion();

    /**
     * This routine is used by some debugging tools to dump the shared memory
     * header in human readable format.
     */
    void DumpSharedMemHeader();

private:
    axLogInstance *m_PLogger;
    int m_LogIdError;
    int m_LogIdWarn;
    int m_LogIdDebug;
    int m_LogIdState;

    /**
     * This is the shared memory ID from shmget().
     */
    int m_ShmId;

    /**
     * This is the shared memory pointer returned by shmat().
     */
    AxSharedMemHeader_v1 *m_PShm;
};

#endif  /* __cplusplus */
#endif  /* _axSharedMem_h_ */

