#ifndef _axStdDefs_h_
#define _axStdDefs_h_

#include <stdint.h>         //uint<n>_t types
#include <x86intrin.h>      //__rdtsc

#ifdef __cplusplus
#   include "axException.h"
#   include "axGuard.h"
#endif  /* __cplusplus */

#ifndef likely
#   define likely(x)        __builtin_expect((x), 1)
#endif  /* likely */
#ifndef unlikely
#   define unlikely(x)      __builtin_expect((x), 0)
#endif  /* unlikely */

#define cl_flush(p)         __asm__ __volatile__("clflush (%0)" :: "r"(p))

#define GET_TIMEBASE(VAR64)      (VAR64) = __rdtsc()

#define cmpxchg(ptr, oldv, newv)  __sync_val_compare_and_swap(ptr, oldv, newv)

/* Display that this code branch is not yet tested. I would like to add some
 * logging capabilities using a mechanism that would allow us to switch between
 * syslog/printf/other but this will do for now.
 */
#define UNTESTEDC() printf("UNTESTED() %s:%d\n", __FILE__, __LINE__)

/**
 * This macro allows use of a constant value potentially byte swapped within a
 * switch statement.
 */
#if __BYTE_ORDER == __BIG_ENDIAN
#define ax_constant_htons(x)    (x)
#else
#define ax_constant_htons(x)    __bswap_constant_16(x)
#endif  /* __BYTE_ORDER */

/**
 * The following are some strings we can use to control the terminal output
 */
#define TERM_CLEAR_SCREEN       "\033[2J"
#define TERM_CURSOR_1_1         "\033[1;1H"
#define TERM_CURSOR_UP_N_LINES  "\033[%uA"

#endif  /* _axStdDefs_h_ */

