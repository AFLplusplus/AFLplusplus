/*
 *  Copyright (c) 2016-2020 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2020 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but portable and without penalties it can run on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others portable hash-functions (which do not use specific
 *     hardware tricks).
 *  3. Not suitable for cryptography.
 *
 * The Future will (be) Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#pragma once

/*****************************************************************************
 *
 * PLEASE PAY ATTENTION TO THE FOLLOWING NOTES
 * about macros definitions which controls t1ha behaviour and/or performance.
 *
 *
 * 1) T1HA_SYS_UNALIGNED_ACCESS = Defines the system/platform/CPU/architecture
 *                                abilities for unaligned data access.
 *
 *    By default, when the T1HA_SYS_UNALIGNED_ACCESS not defined,
 *    it will defined on the basis hardcoded knowledge about of capabilities
 *    of most common CPU architectures. But you could override this
 *    default behavior when build t1ha library itself:
 *
 *      // To disable unaligned access at all.
 *      #define T1HA_SYS_UNALIGNED_ACCESS 0
 *
 *      // To enable unaligned access, but indicate that it significantly slow.
 *      #define T1HA_SYS_UNALIGNED_ACCESS 1
 *
 *      // To enable unaligned access, and indicate that it effecient.
 *      #define T1HA_SYS_UNALIGNED_ACCESS 2
 *
 *
 * 2) T1HA_USE_FAST_ONESHOT_READ = Controls the data reads at the end of buffer.
 *
 *    When defined to non-zero, t1ha will use 'one shot' method for reading
 *    up to 8 bytes at the end of data. In this case just the one 64-bit read
 *    will be performed even when the available less than 8 bytes.
 *
 *    This is little bit faster that switching by length of data tail.
 *    Unfortunately this will triggering a false-positive alarms from Valgrind,
 *    AddressSanitizer and other similar tool.
 *
 *    By default, t1ha defines it to 1, but you could override this
 *    default behavior when build t1ha library itself:
 *
 *      // For little bit faster and small code.
 *      #define T1HA_USE_FAST_ONESHOT_READ 1
 *
 *      // For calmness if doubt.
 *      #define T1HA_USE_FAST_ONESHOT_READ 0
 *
 *
 * 3) T1HA0_RUNTIME_SELECT = Controls choice fastest function in runtime.
 *
 *    t1ha library offers the t1ha0() function as the fastest for current CPU.
 *    But actual CPU's features/capabilities and may be significantly different,
 *    especially on x86 platform. Therefore, internally, t1ha0() may require
 *    dynamic dispatching for choice best implementation.
 *
 *    By default, t1ha enables such runtime choice and (may be) corresponding
 *    indirect calls if it reasonable, but you could override this default
 *    behavior when build t1ha library itself:
 *
 *      // To enable runtime choice of fastest implementation.
 *      #define T1HA0_RUNTIME_SELECT 1
 *
 *      // To disable runtime choice of fastest implementation.
 *      #define T1HA0_RUNTIME_SELECT 0
 *
 *    When T1HA0_RUNTIME_SELECT is nonzero the t1ha0_resolve() function could
 *    be used to get actual t1ha0() implementation address at runtime. This is
 *    useful for two cases:
 *      - calling by local pointer-to-function usually is little
 *        bit faster (less overhead) than via a PLT thru the DSO boundary.
 *      - GNU Indirect functions (see below) don't supported by environment
 *        and calling by t1ha0_funcptr is not available and/or expensive.
 *
 * 4) T1HA_USE_INDIRECT_FUNCTIONS = Controls usage of GNU Indirect functions.
 *
 *    In continue of T1HA0_RUNTIME_SELECT the T1HA_USE_INDIRECT_FUNCTIONS
 *    controls usage of ELF indirect functions feature. In general, when
 *    available, this reduces overhead of indirect function's calls though
 *    a DSO-bundary (https://sourceware.org/glibc/wiki/GNU_IFUNC).
 *
 *    By default, t1ha engage GNU Indirect functions when it available
 *    and useful, but you could override this default behavior when build
 *    t1ha library itself:
 *
 *      // To enable use of GNU ELF Indirect functions.
 *      #define T1HA_USE_INDIRECT_FUNCTIONS 1
 *
 *      // To disable use of GNU ELF Indirect functions. This may be useful
 *      // if the actual toolchain or the system's loader don't support ones.
 *      #define T1HA_USE_INDIRECT_FUNCTIONS 0
 *
 * 5) T1HA0_AESNI_AVAILABLE = Controls AES-NI detection and dispatching on x86.
 *
 *    In continue of T1HA0_RUNTIME_SELECT the T1HA0_AESNI_AVAILABLE controls
 *    detection and usage of AES-NI CPU's feature. On the other hand, this
 *    requires compiling parts of t1ha library with certain properly options,
 *    and could be difficult or inconvenient in some cases.
 *
 *    By default, t1ha engade AES-NI for t1ha0() on the x86 platform, but
 *    you could override this default behavior when build t1ha library itself:
 *
 *      // To disable detection and usage of AES-NI instructions for t1ha0().
 *      // This may be useful when you unable to build t1ha library properly
 *      // or known that AES-NI will be unavailable at the deploy.
 *      #define T1HA0_AESNI_AVAILABLE 0
 *
 *      // To force detection and usage of AES-NI instructions for t1ha0(),
 *      // but I don't known reasons to anybody would need this.
 *      #define T1HA0_AESNI_AVAILABLE 1
 *
 * 6) T1HA0_DISABLED, T1HA1_DISABLED, T1HA2_DISABLED = Controls availability of
 *    t1ha functions.
 *
 *    In some cases could be useful to import/use only few of t1ha functions
 *    or just the one. So, this definitions allows disable corresponding parts
 *    of t1ha library.
 *
 *      // To disable t1ha0(), t1ha0_32le(), t1ha0_32be() and all AES-NI.
 *      #define T1HA0_DISABLED
 *
 *      // To disable t1ha1_le() and t1ha1_be().
 *      #define T1HA1_DISABLED
 *
 *      // To disable t1ha2_atonce(), t1ha2_atonce128() and so on.
 *      #define T1HA2_DISABLED
 *
 *****************************************************************************/

#define T1HA_VERSION_MAJOR 2
#define T1HA_VERSION_MINOR 1
#define T1HA_VERSION_RELEASE 1

#ifndef __has_attribute
  #define __has_attribute(x) (0)
#endif

#ifndef __has_include
  #define __has_include(x) (0)
#endif

#ifndef __GNUC_PREREQ
  #if defined(__GNUC__) && defined(__GNUC_MINOR__)
    #define __GNUC_PREREQ(maj, min) \
      ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
  #else
    #define __GNUC_PREREQ(maj, min) 0
  #endif
#endif                                                     /* __GNUC_PREREQ */

#ifndef __CLANG_PREREQ
  #ifdef __clang__
    #define __CLANG_PREREQ(maj, min) \
      ((__clang_major__ << 16) + __clang_minor__ >= ((maj) << 16) + (min))
  #else
    #define __CLANG_PREREQ(maj, min) (0)
  #endif
#endif                                                    /* __CLANG_PREREQ */

#ifndef __LCC_PREREQ
  #ifdef __LCC__
    #define __LCC_PREREQ(maj, min) \
      ((__LCC__ << 16) + __LCC_MINOR__ >= ((maj) << 16) + (min))
  #else
    #define __LCC_PREREQ(maj, min) (0)
  #endif
#endif                                                      /* __LCC_PREREQ */

/*****************************************************************************/

#ifdef _MSC_VER
  /* Avoid '16' bytes padding added after data member 't1ha_context::total'
   * and other warnings from std-headers if warning-level > 3. */
  #pragma warning(push, 3)
#endif

#if defined(__cplusplus) && __cplusplus >= 201103L
  #include <climits>
  #include <cstddef>
  #include <cstdint>
#else
  #include <limits.h>
  #include <stddef.h>
  #include <stdint.h>
#endif

/*****************************************************************************/

#if defined(i386) || defined(__386) || defined(__i386) || defined(__i386__) || \
    defined(i486) || defined(__i486) || defined(__i486__) ||                   \
    defined(i586) | defined(__i586) || defined(__i586__) || defined(i686) ||   \
    defined(__i686) || defined(__i686__) || defined(_M_IX86) ||                \
    defined(_X86_) || defined(__THW_INTEL__) || defined(__I86__) ||            \
    defined(__INTEL__) || defined(__x86_64) || defined(__x86_64__) ||          \
    defined(__amd64__) || defined(__amd64) || defined(_M_X64) ||               \
    defined(_M_AMD64) || defined(__IA32__) || defined(__INTEL__)
  #ifndef __ia32__
    /* LY: define neutral __ia32__ for x86 and x86-64 archs */
    #define __ia32__ 1
  #endif                                                        /* __ia32__ */
  #if !defined(__amd64__) && (defined(__x86_64) || defined(__x86_64__) || \
                              defined(__amd64) || defined(_M_X64))
    /* LY: define trusty __amd64__ for all AMD64/x86-64 arch */
    #define __amd64__ 1
  #endif                                                       /* __amd64__ */
#endif                                                           /* all x86 */

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    !defined(__ORDER_BIG_ENDIAN__)

/* *INDENT-OFF* */
/* clang-format off */

#if defined(__GLIBC__) || defined(__GNU_LIBRARY__) || defined(__ANDROID__) ||  \
    defined(HAVE_ENDIAN_H) || __has_include(<endian.h>)
#include <endian.h>
#elif defined(__APPLE__) || defined(__MACH__) || defined(__OpenBSD__) ||       \
    defined(HAVE_MACHINE_ENDIAN_H) || __has_include(<machine/endian.h>)
#include <machine/endian.h>
#elif defined(HAVE_SYS_ISA_DEFS_H) || __has_include(<sys/isa_defs.h>)
#include <sys/isa_defs.h>
#elif (defined(HAVE_SYS_TYPES_H) && defined(HAVE_SYS_ENDIAN_H)) ||             \
    (__has_include(<sys/types.h>) && __has_include(<sys/endian.h>))
#include <sys/endian.h>
#include <sys/types.h>
#elif defined(__bsdi__) || defined(__DragonFly__) || defined(__FreeBSD__) ||   \
    defined(__NETBSD__) || defined(__NetBSD__) ||                              \
    defined(HAVE_SYS_PARAM_H) || __has_include(<sys/param.h>)
#include <sys/param.h>
#endif                                                                /* OS */

/* *INDENT-ON* */
/* clang-format on */

  #if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
    #define __ORDER_LITTLE_ENDIAN__ __LITTLE_ENDIAN
    #define __ORDER_BIG_ENDIAN__ __BIG_ENDIAN
    #define __BYTE_ORDER__ __BYTE_ORDER
  #elif defined(_BYTE_ORDER) && defined(_LITTLE_ENDIAN) && defined(_BIG_ENDIAN)
    #define __ORDER_LITTLE_ENDIAN__ _LITTLE_ENDIAN
    #define __ORDER_BIG_ENDIAN__ _BIG_ENDIAN
    #define __BYTE_ORDER__ _BYTE_ORDER
  #else
    #define __ORDER_LITTLE_ENDIAN__ 1234
    #define __ORDER_BIG_ENDIAN__ 4321

    #if defined(__LITTLE_ENDIAN__) ||                                        \
        (defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)) ||                \
        defined(__ARMEL__) || defined(__THUMBEL__) ||                        \
        defined(__AARCH64EL__) || defined(__MIPSEL__) || defined(_MIPSEL) || \
        defined(__MIPSEL) || defined(_M_ARM) || defined(_M_ARM64) ||         \
        defined(__e2k__) || defined(__elbrus_4c__) ||                        \
        defined(__elbrus_8c__) || defined(__bfin__) || defined(__BFIN__) ||  \
        defined(__ia64__) || defined(_IA64) || defined(__IA64__) ||          \
        defined(__ia64) || defined(_M_IA64) || defined(__itanium__) ||       \
        defined(__ia32__) || defined(__CYGWIN__) || defined(_WIN64) ||       \
        defined(_WIN32) || defined(__TOS_WIN__) || defined(__WINDOWS__)
      #define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__

    #elif defined(__BIG_ENDIAN__) ||                                         \
        (defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)) ||                \
        defined(__ARMEB__) || defined(__THUMBEB__) ||                        \
        defined(__AARCH64EB__) || defined(__MIPSEB__) || defined(_MIPSEB) || \
        defined(__MIPSEB) || defined(__m68k__) || defined(M68000) ||         \
        defined(__hppa__) || defined(__hppa) || defined(__HPPA__) ||         \
        defined(__sparc__) || defined(__sparc) || defined(__370__) ||        \
        defined(__THW_370__) || defined(__s390__) || defined(__s390x__) ||   \
        defined(__SYSC_ZARCH__)
      #define __BYTE_ORDER__ __ORDER_BIG_ENDIAN__

    #else
      #error __BYTE_ORDER__ should be defined.
    #endif                                                          /* Arch */

  #endif
#endif /* __BYTE_ORDER__ || __ORDER_LITTLE_ENDIAN__ || __ORDER_BIG_ENDIAN__ */

/*****************************************************************************/

#ifndef __dll_export
  #if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    #if defined(__GNUC__) || __has_attribute(dllexport)
      #define __dll_export __attribute__((dllexport))
    #else
      #define __dll_export __declspec(dllexport)
    #endif
  #elif defined(__GNUC__) || __has_attribute(__visibility__)
    #define __dll_export __attribute__((__visibility__("default")))
  #else
    #define __dll_export
  #endif
#endif                                                      /* __dll_export */

#ifndef __dll_import
  #if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    #if defined(__GNUC__) || __has_attribute(dllimport)
      #define __dll_import __attribute__((dllimport))
    #else
      #define __dll_import __declspec(dllimport)
    #endif
  #elif defined(__GNUC__) || __has_attribute(__visibility__)
    #define __dll_import __attribute__((__visibility__("default")))
  #else
    #define __dll_import
  #endif
#endif                                                      /* __dll_import */

#ifndef __force_inline
  #ifdef _MSC_VER
    #define __force_inline __forceinline
  #elif __GNUC_PREREQ(3, 2) || __has_attribute(__always_inline__)
    #define __force_inline __inline __attribute__((__always_inline__))
  #else
    #define __force_inline __inline
  #endif
#endif                                                    /* __force_inline */

#ifndef T1HA_API
  #if defined(t1ha_EXPORTS)
    #define T1HA_API __dll_export
  #elif defined(t1ha_IMPORTS)
    #define T1HA_API __dll_import
  #else
    #define T1HA_API
  #endif
#endif                                                          /* T1HA_API */

#if defined(_MSC_VER) && defined(__ia32__)
  #define T1HA_ALIGN_PREFIX __declspec(align(32)) /* required only for SIMD */
#else
  #define T1HA_ALIGN_PREFIX
#endif                                                          /* _MSC_VER */

#if defined(__GNUC__) && defined(__ia32__)
  #define T1HA_ALIGN_SUFFIX \
    __attribute__((__aligned__(32)))              /* required only for SIMD */
#else
  #define T1HA_ALIGN_SUFFIX
#endif                                                           /* GCC x86 */

#ifndef T1HA_USE_INDIRECT_FUNCTIONS
  /* GNU ELF indirect functions usage control. For more info please see
   * https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
   * and https://sourceware.org/glibc/wiki/GNU_IFUNC */
  #if defined(__ELF__) && defined(__amd64__) &&                      \
      (__has_attribute(__ifunc__) ||                                 \
       (!defined(__clang__) && defined(__GNUC__) && __GNUC__ >= 4 && \
        !defined(__SANITIZE_ADDRESS__) && !defined(__SSP_ALL__)))
    /* Enable gnu_indirect_function by default if :
     *  - ELF AND x86_64
     *  - attribute(__ifunc__) is available OR
     *    GCC >= 4 WITHOUT -fsanitize=address NOR -fstack-protector-all */
    #define T1HA_USE_INDIRECT_FUNCTIONS 1
  #else
    #define T1HA_USE_INDIRECT_FUNCTIONS 0
  #endif
#endif                                       /* T1HA_USE_INDIRECT_FUNCTIONS */

#if __GNUC_PREREQ(4, 0)
  #pragma GCC visibility push(hidden)
#endif                                                /* __GNUC_PREREQ(4,0) */

#ifdef __cplusplus
extern "C" {

#endif

typedef union T1HA_ALIGN_PREFIX t1ha_state256 {

  uint8_t  bytes[32];
  uint32_t u32[8];
  uint64_t u64[4];
  struct {

    uint64_t a, b, c, d;

  } n;

} t1ha_state256_t T1HA_ALIGN_SUFFIX;

typedef struct t1ha_context {

  t1ha_state256_t state;
  t1ha_state256_t buffer;
  size_t          partial;
  uint64_t        total;

} t1ha_context_t;

#ifdef _MSC_VER
  #pragma warning(pop)
#endif

/******************************************************************************
 *
 * Self-testing API.
 *
 * Unfortunately, some compilers (exactly only Microsoft Visual C/C++) has
 * a bugs which leads t1ha-functions to produce wrong results. This API allows
 * check the correctness of the actual code in runtime.
 *
 * All check-functions returns 0 on success, or -1 in case the corresponding
 * hash-function failed verification. PLEASE, always perform such checking at
 * initialization of your code, if you using MSVC or other troubleful compilers.
 */

T1HA_API int t1ha_selfcheck__all_enabled(void);

#ifndef T1HA2_DISABLED
T1HA_API int t1ha_selfcheck__t1ha2_atonce(void);
T1HA_API int t1ha_selfcheck__t1ha2_atonce128(void);
T1HA_API int t1ha_selfcheck__t1ha2_stream(void);
T1HA_API int t1ha_selfcheck__t1ha2(void);
#endif                                                    /* T1HA2_DISABLED */

#ifndef T1HA1_DISABLED
T1HA_API int t1ha_selfcheck__t1ha1_le(void);
T1HA_API int t1ha_selfcheck__t1ha1_be(void);
T1HA_API int t1ha_selfcheck__t1ha1(void);
#endif                                                    /* T1HA1_DISABLED */

#ifndef T1HA0_DISABLED
T1HA_API int t1ha_selfcheck__t1ha0_32le(void);
T1HA_API int t1ha_selfcheck__t1ha0_32be(void);
T1HA_API int t1ha_selfcheck__t1ha0(void);

  /* Define T1HA0_AESNI_AVAILABLE to 0 for disable AES-NI support. */
  #ifndef T1HA0_AESNI_AVAILABLE
    #if defined(__e2k__) || \
        (defined(__ia32__) && (!defined(_M_IX86) || _MSC_VER > 1800))
      #define T1HA0_AESNI_AVAILABLE 1
    #else
      #define T1HA0_AESNI_AVAILABLE 0
    #endif
  #endif                                    /* ifndef T1HA0_AESNI_AVAILABLE */

  #if T1HA0_AESNI_AVAILABLE
T1HA_API int t1ha_selfcheck__t1ha0_ia32aes_noavx(void);
T1HA_API int t1ha_selfcheck__t1ha0_ia32aes_avx(void);
    #ifndef __e2k__
T1HA_API int t1ha_selfcheck__t1ha0_ia32aes_avx2(void);
    #endif
  #endif                                        /* if T1HA0_AESNI_AVAILABLE */
#endif                                                    /* T1HA0_DISABLED */

/******************************************************************************
 *
 *  t1ha2 = 64 and 128-bit, SLIGHTLY MORE ATTENTION FOR QUALITY AND STRENGTH.
 *
 *    - The recommended version of "Fast Positive Hash" with good quality
 *      for checksum, hash tables and fingerprinting.
 *    - Portable and extremely efficiency on modern 64-bit CPUs.
 *      Designed for 64-bit little-endian platforms,
 *      in other cases will runs slowly.
 *    - Great quality of hashing and still faster than other non-t1ha hashes.
 *      Provides streaming mode and 128-bit result.
 *
 * Note: Due performance reason 64- and 128-bit results are completely
 *       different each other, i.e. 64-bit result is NOT any part of 128-bit.
 */
#ifndef T1HA2_DISABLED

/* The at-once variant with 64-bit result */
T1HA_API uint64_t t1ha2_atonce(const void *data, size_t length, uint64_t seed);

/* The at-once variant with 128-bit result.
 * Argument `extra_result` is NOT optional and MUST be valid.
 * The high 64-bit part of 128-bit hash will be always unconditionally
 * stored to the address given by `extra_result` argument. */
T1HA_API uint64_t t1ha2_atonce128(uint64_t *__restrict extra_result,
                                  const void *__restrict data, size_t length,
                                  uint64_t seed);

/* The init/update/final trinity for streaming.
 * Return 64 or 128-bit result depentently from `extra_result` argument. */
T1HA_API void t1ha2_init(t1ha_context_t *ctx, uint64_t seed_x, uint64_t seed_y);
T1HA_API void t1ha2_update(t1ha_context_t *__restrict ctx,
                           const void *__restrict data, size_t length);

/* Argument `extra_result` is optional and MAY be NULL.
 *  - If `extra_result` is NOT NULL then the 128-bit hash will be calculated,
 *    and high 64-bit part of it will be stored to the address given
 *    by `extra_result` argument.
 *  - Otherwise the 64-bit hash will be calculated
 *    and returned from function directly.
 *
 * Note: Due performance reason 64- and 128-bit results are completely
 *       different each other, i.e. 64-bit result is NOT any part of 128-bit. */
T1HA_API uint64_t t1ha2_final(t1ha_context_t *__restrict ctx,
                              uint64_t *__restrict extra_result /* optional */);

#endif                                                    /* T1HA2_DISABLED */

/******************************************************************************
 *
 *  t1ha1 = 64-bit, BASELINE FAST PORTABLE HASH:
 *
 *    - Runs faster on 64-bit platforms in other cases may runs slowly.
 *    - Portable and stable, returns same 64-bit result
 *      on all architectures and CPUs.
 *    - Unfortunately it fails the "strict avalanche criteria",
 *      see test results at https://github.com/demerphq/smhasher.
 *
 *      This flaw is insignificant for the t1ha1() purposes and imperceptible
 *      from a practical point of view.
 *      However, nowadays this issue has resolved in the next t1ha2(),
 *      that was initially planned to providing a bit more quality.
 */
#ifndef T1HA1_DISABLED

/* The little-endian variant. */
T1HA_API uint64_t t1ha1_le(const void *data, size_t length, uint64_t seed);

/* The big-endian variant. */
T1HA_API uint64_t t1ha1_be(const void *data, size_t length, uint64_t seed);

#endif                                                    /* T1HA1_DISABLED */

/******************************************************************************
 *
 *  t1ha0 = 64-bit, JUST ONLY FASTER:
 *
 *    - Provides fast-as-possible hashing for current CPU, including
 *      32-bit systems and engaging the available hardware acceleration.
 *    - It is a facade that selects most quick-and-dirty hash
 *      for the current processor. For instance, on IA32 (x86) actual function
 *      will be selected in runtime, depending on current CPU capabilities
 *
 * BE CAREFUL!!!  THIS IS MEANS:
 *
 *   1. The quality of hash is a subject for tradeoffs with performance.
 *      So, the quality and strength of t1ha0() may be lower than t1ha1(),
 *      especially on 32-bit targets, but then much faster.
 *      However, guaranteed that it passes all SMHasher tests.
 *
 *   2. No warranty that the hash result will be same for particular
 *      key on another machine or another version of libt1ha.
 *
 *      Briefly, such hash-results and their derivatives, should be
 *      used only in runtime, but should not be persist or transferred
 *      over a network.
 *
 *
 *  When T1HA0_RUNTIME_SELECT is nonzero the t1ha0_resolve() function could
 *  be used to get actual t1ha0() implementation address at runtime. This is
 *  useful for two cases:
 *    - calling by local pointer-to-function usually is little
 *      bit faster (less overhead) than via a PLT thru the DSO boundary.
 *    - GNU Indirect functions (see below) don't supported by environment
 *      and calling by t1ha0_funcptr is not available and/or expensive.
 */

#ifndef T1HA0_DISABLED

/* The little-endian variant for 32-bit CPU. */
uint64_t t1ha0_32le(const void *data, size_t length, uint64_t seed);
/* The big-endian variant for 32-bit CPU. */
uint64_t t1ha0_32be(const void *data, size_t length, uint64_t seed);

  /* Define T1HA0_AESNI_AVAILABLE to 0 for disable AES-NI support. */
  #ifndef T1HA0_AESNI_AVAILABLE
    #if defined(__e2k__) || \
        (defined(__ia32__) && (!defined(_M_IX86) || _MSC_VER > 1800))
      #define T1HA0_AESNI_AVAILABLE 1
    #else
      #define T1HA0_AESNI_AVAILABLE 0
    #endif
  #endif                                           /* T1HA0_AESNI_AVAILABLE */

  /* Define T1HA0_RUNTIME_SELECT to 0 for disable dispatching t1ha0 at runtime.
   */
  #ifndef T1HA0_RUNTIME_SELECT
    #if T1HA0_AESNI_AVAILABLE && !defined(__e2k__)
      #define T1HA0_RUNTIME_SELECT 1
    #else
      #define T1HA0_RUNTIME_SELECT 0
    #endif
  #endif                                            /* T1HA0_RUNTIME_SELECT */

  #if !T1HA0_RUNTIME_SELECT && !defined(T1HA0_USE_DEFINE)
    #if defined(__LCC__)
      #define T1HA0_USE_DEFINE 1
    #else
      #define T1HA0_USE_DEFINE 0
    #endif
  #endif                                                /* T1HA0_USE_DEFINE */

  #if T1HA0_AESNI_AVAILABLE
uint64_t t1ha0_ia32aes_noavx(const void *data, size_t length, uint64_t seed);
uint64_t t1ha0_ia32aes_avx(const void *data, size_t length, uint64_t seed);
    #ifndef __e2k__
uint64_t t1ha0_ia32aes_avx2(const void *data, size_t length, uint64_t seed);
    #endif
  #endif                                           /* T1HA0_AESNI_AVAILABLE */

  #if T1HA0_RUNTIME_SELECT
typedef uint64_t (*t1ha0_function_t)(const void *, size_t, uint64_t);
T1HA_API t1ha0_function_t t1ha0_resolve(void);
    #if T1HA_USE_INDIRECT_FUNCTIONS
T1HA_API uint64_t t1ha0(const void *data, size_t length, uint64_t seed);
    #else
/* Otherwise function pointer will be used.
 * Unfortunately this may cause some overhead calling. */
T1HA_API extern uint64_t (*t1ha0_funcptr)(const void *data, size_t length,
                                          uint64_t seed);
static __force_inline uint64_t t1ha0(const void *data, size_t length,
                                     uint64_t seed) {

  return t1ha0_funcptr(data, length, seed);

}

    #endif                                   /* T1HA_USE_INDIRECT_FUNCTIONS */

  #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

    #if T1HA0_USE_DEFINE

      #if (UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul) && \
          (!defined(T1HA1_DISABLED) || !defined(T1HA2_DISABLED))
        #if defined(T1HA1_DISABLED)
          #define t1ha0 t1ha2_atonce
        #else
          #define t1ha0 t1ha1_be
        #endif                                            /* T1HA1_DISABLED */
      #else                                                        /* 32/64 */
        #define t1ha0 t1ha0_32be
      #endif                                                       /* 32/64 */

    #else                                               /* T1HA0_USE_DEFINE */

static __force_inline uint64_t t1ha0(const void *data, size_t length,
                                     uint64_t seed) {

      #if (UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul) && \
          (!defined(T1HA1_DISABLED) || !defined(T1HA2_DISABLED))
        #if defined(T1HA1_DISABLED)
  return t1ha2_atonce(data, length, seed);
        #else
  return t1ha1_be(data, length, seed);
        #endif                                            /* T1HA1_DISABLED */
      #else                                                        /* 32/64 */
  return t1ha0_32be(data, length, seed);
      #endif                                                       /* 32/64 */

}

    #endif                                             /* !T1HA0_USE_DEFINE */

  #else  /* !T1HA0_RUNTIME_SELECT && __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__ */

    #if T1HA0_USE_DEFINE

      #if (UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul) && \
          (!defined(T1HA1_DISABLED) || !defined(T1HA2_DISABLED))
        #if defined(T1HA1_DISABLED)
          #define t1ha0 t1ha2_atonce
        #else
          #define t1ha0 t1ha1_le
        #endif                                            /* T1HA1_DISABLED */
      #else                                                        /* 32/64 */
        #define t1ha0 t1ha0_32le
      #endif                                                       /* 32/64 */

    #else

static __force_inline uint64_t t1ha0(const void *data, size_t length,
                                     uint64_t seed) {

      #if (UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul) && \
          (!defined(T1HA1_DISABLED) || !defined(T1HA2_DISABLED))
        #if defined(T1HA1_DISABLED)
  return t1ha2_atonce(data, length, seed);
        #else
  return t1ha1_le(data, length, seed);
        #endif                                            /* T1HA1_DISABLED */
      #else                                                        /* 32/64 */
  return t1ha0_32le(data, length, seed);
      #endif                                                       /* 32/64 */

}

    #endif                                             /* !T1HA0_USE_DEFINE */

  #endif                                           /* !T1HA0_RUNTIME_SELECT */

#endif                                                    /* T1HA0_DISABLED */

#ifdef __cplusplus

}

#endif

#if __GNUC_PREREQ(4, 0)
  #pragma GCC visibility pop
#endif                                                /* __GNUC_PREREQ(4,0) */

