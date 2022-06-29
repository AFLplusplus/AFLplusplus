/*
   american fuzzy lop++ - debug / error handling macros
   ----------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _HAVE_DEBUG_H
#define _HAVE_DEBUG_H

#include <errno.h>

#include "types.h"
#include "config.h"

/*******************
 * Terminal colors *
 *******************/

#ifndef MESSAGES_TO_STDOUT
  #define MESSAGES_TO_STDOUT
#endif

#ifdef USE_COLOR

  #define cBLK "\x1b[0;30m"
  #define cRED "\x1b[0;31m"
  #define cGRN "\x1b[0;32m"
  #define cBRN "\x1b[0;33m"
  #define cBLU "\x1b[0;34m"
  #define cMGN "\x1b[0;35m"
  #define cCYA "\x1b[0;36m"
  #define cLGR "\x1b[0;37m"
  #define cGRA "\x1b[1;90m"
  #define cLRD "\x1b[1;91m"
  #define cLGN "\x1b[1;92m"
  #define cYEL "\x1b[1;93m"
  #define cLBL "\x1b[1;94m"
  #define cPIN "\x1b[1;95m"
  #define cLCY "\x1b[1;96m"
  #define cBRI "\x1b[1;97m"
  #define cRST "\x1b[0m"

  #define bgBLK "\x1b[40m"
  #define bgRED "\x1b[41m"
  #define bgGRN "\x1b[42m"
  #define bgBRN "\x1b[43m"
  #define bgBLU "\x1b[44m"
  #define bgMGN "\x1b[45m"
  #define bgCYA "\x1b[46m"
  #define bgLGR "\x1b[47m"
  #define bgGRA "\x1b[100m"
  #define bgLRD "\x1b[101m"
  #define bgLGN "\x1b[102m"
  #define bgYEL "\x1b[103m"
  #define bgLBL "\x1b[104m"
  #define bgPIN "\x1b[105m"
  #define bgLCY "\x1b[106m"
  #define bgBRI "\x1b[107m"

#else

  #define cBLK ""
  #define cRED ""
  #define cGRN ""
  #define cBRN ""
  #define cBLU ""
  #define cMGN ""
  #define cCYA ""
  #define cLGR ""
  #define cGRA ""
  #define cLRD ""
  #define cLGN ""
  #define cYEL ""
  #define cLBL ""
  #define cPIN ""
  #define cLCY ""
  #define cBRI ""
  #define cRST ""

  #define bgBLK ""
  #define bgRED ""
  #define bgGRN ""
  #define bgBRN ""
  #define bgBLU ""
  #define bgMGN ""
  #define bgCYA ""
  #define bgLGR ""
  #define bgGRA ""
  #define bgLRD ""
  #define bgLGN ""
  #define bgYEL ""
  #define bgLBL ""
  #define bgPIN ""
  #define bgLCY ""
  #define bgBRI ""

#endif                                                        /* ^USE_COLOR */

/*************************
 * Box drawing sequences *
 *************************/

#ifdef FANCY_BOXES

  #define SET_G1 "\x1b)0"                      /* Set G1 for box drawing    */
  #define RESET_G1 "\x1b)B"                    /* Reset G1 to ASCII         */
  #define bSTART "\x0e"                        /* Enter G1 drawing mode     */
  #define bSTOP "\x0f"                         /* Leave G1 drawing mode     */
  #define bH "q"                               /* Horizontal line           */
  #define bV "x"                               /* Vertical line             */
  #define bLT "l"                              /* Left top corner           */
  #define bRT "k"                              /* Right top corner          */
  #define bLB "m"                              /* Left bottom corner        */
  #define bRB "j"                              /* Right bottom corner       */
  #define bX "n"                               /* Cross                     */
  #define bVR "t"                              /* Vertical, branch right    */
  #define bVL "u"                              /* Vertical, branch left     */
  #define bHT "v"                              /* Horizontal, branch top    */
  #define bHB "w"                              /* Horizontal, branch bottom */

#else

  #define SET_G1 ""
  #define RESET_G1 ""
  #define bSTART ""
  #define bSTOP ""
  #define bH "-"
  #define bV "|"
  #define bLT "+"
  #define bRT "+"
  #define bLB "+"
  #define bRB "+"
  #define bX "+"
  #define bVR "+"
  #define bVL "+"
  #define bHT "+"
  #define bHB "+"

#endif                                                      /* ^FANCY_BOXES */

/***********************
 * Misc terminal codes *
 ***********************/

#define TERM_HOME "\x1b[H"
#define TERM_CLEAR TERM_HOME "\x1b[2J"
#define cEOL "\x1b[0K"
#define CURSOR_HIDE "\x1b[?25l"
#define CURSOR_SHOW "\x1b[?25h"

/************************
 * Debug & error macros *
 ************************/

#if defined USE_COLOR && !defined ALWAYS_COLORED
  #include <unistd.h>
  #pragma GCC diagnostic ignored "-Wformat-security"
static inline const char *colorfilter(const char *x) {

  static int once = 1;
  static int disabled = 0;

  if (once) {

    /* when there is no tty -> we always want filtering
     * when AFL_NO_UI is set filtering depends on AFL_NO_COLOR
     * otherwise we want always colors
     */
    disabled =
        isatty(2) && (!getenv("AFL_NO_UI") ||
                      (!getenv("AFL_NO_COLOR") && !getenv("AFL_NO_COLOUR")));
    once = 0;

  }

  if (likely(disabled)) return x;

  static char monochromestring[4096];
  char *      d = monochromestring;
  int         in_seq = 0;

  while (*x) {

    if (in_seq && *x == 'm') {

      in_seq = 0;

    } else {

      if (!in_seq && *x == '\x1b') { in_seq = 1; }
      if (!in_seq) { *d++ = *x; }

    }

    ++x;

  }

  *d = '\0';
  return monochromestring;

}

#else
  #define colorfilter(x) x                        /* no filtering necessary */
#endif

/* macro magic to transform the first parameter to SAYF
 * through colorfilter which strips coloring */
#define GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, \
                  _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26,  \
                  _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38,  \
                  _39, _40, NAME, ...)                                         \
  NAME

#define SAYF(...)                                                           \
  GET_MACRO(__VA_ARGS__, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N,    \
            SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, \
            SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, \
            SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, \
            SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, SAYF_N, \
            SAYF_N, SAYF_1)                                                 \
  (__VA_ARGS__)

#define SAYF_1(x) MY_SAYF(colorfilter(x))
#define SAYF_N(x, ...) MY_SAYF(colorfilter(x), __VA_ARGS__)

/* Just print stuff to the appropriate stream. */
#ifdef MESSAGES_TO_STDOUT
  #define MY_SAYF(x...) printf(x)
#else
  #define MY_SAYF(x...) fprintf(stderr, x)
#endif                                               /* ^MESSAGES_TO_STDOUT */

/* Show a prefixed warning. */

#define WARNF(x...)                            \
  do {                                         \
                                               \
    SAYF(cYEL "[!] " cBRI "WARNING: " cRST x); \
    SAYF(cRST "\n");                           \
                                               \
  } while (0)

/* Show a prefixed "doing something" message. */

#define ACTF(x...)            \
  do {                        \
                              \
    SAYF(cLBL "[*] " cRST x); \
    SAYF(cRST "\n");          \
                              \
  } while (0)

/* Show a prefixed "success" message. */

#define OKF(x...)             \
  do {                        \
                              \
    SAYF(cLGN "[+] " cRST x); \
    SAYF(cRST "\n");          \
                              \
  } while (0)

/* Show a prefixed fatal error message (not used in afl). */

#define BADF(x...)              \
  do {                          \
                                \
    SAYF(cLRD "\n[-] " cRST x); \
    SAYF(cRST "\n");            \
                                \
  } while (0)

/* Die with a verbose non-OS fatal error message. */

#define FATAL(x...)                                                      \
  do {                                                                   \
                                                                         \
    SAYF(bSTOP RESET_G1 CURSOR_SHOW cRST cLRD                            \
         "\n[-] PROGRAM ABORT : " cRST   x);                               \
    SAYF(cLRD "\n         Location : " cRST "%s(), %s:%u\n\n", __func__, \
         __FILE__, (u32)__LINE__);                                       \
    exit(1);                                                             \
                                                                         \
  } while (0)

/* Die by calling abort() to provide a core dump. */

#define ABORT(x...)                                                      \
  do {                                                                   \
                                                                         \
    SAYF(bSTOP RESET_G1 CURSOR_SHOW cRST cLRD                            \
         "\n[-] PROGRAM ABORT : " cRST   x);                               \
    SAYF(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n\n", __func__, \
         __FILE__, (u32)__LINE__);                                       \
    abort();                                                             \
                                                                         \
  } while (0)

/* Die while also including the output of perror(). */

#define PFATAL(x...)                                                   \
  do {                                                                 \
                                                                       \
    fflush(stdout);                                                    \
    SAYF(bSTOP RESET_G1 CURSOR_SHOW cRST cLRD                          \
         "\n[-]  SYSTEM ERROR : " cRST   x);                             \
    SAYF(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n", __func__, \
         __FILE__, (u32)__LINE__);                                     \
    SAYF(cLRD "       OS message : " cRST "%s\n", strerror(errno));    \
    exit(1);                                                           \
                                                                       \
  } while (0)

/* Die with FATAL() or PFATAL() depending on the value of res (used to
   interpret different failure modes for read(), write(), etc). */

#define RPFATAL(res, x...) \
  do {                     \
                           \
    if (res < 0)           \
      PFATAL(x);           \
    else                   \
      FATAL(x);            \
                           \
  } while (0)

/* Show a prefixed debug output. */

#define DEBUGF(x...)                                    \
  do {                                                  \
                                                        \
    fprintf(stderr, cMGN "[D] " cBRI "DEBUG: " cRST x); \
    fprintf(stderr, cRST "");                           \
                                                        \
  } while (0)

/* Error-checking versions of read() and write() that call RPFATAL() as
   appropriate. */

#define ck_write(fd, buf, len, fn)                                            \
  do {                                                                        \
                                                                              \
    if (len <= 0) break;                                                      \
    int _fd = (fd);                                                           \
    s32 _written = 0, _off = 0, _len = (s32)(len);                            \
                                                                              \
    do {                                                                      \
                                                                              \
      s32 _res = write(_fd, (buf) + _off, _len);                              \
      if (_res != _len && (_res > 0 && _written + _res != _len)) {            \
                                                                              \
        if (_res > 0) {                                                       \
                                                                              \
          _written += _res;                                                   \
          _len -= _res;                                                       \
          _off += _res;                                                       \
                                                                              \
        } else {                                                              \
                                                                              \
          RPFATAL(_res, "Short write to %s, fd %d (%d of %d bytes)", fn, _fd, \
                  _res, _len);                                                \
                                                                              \
        }                                                                     \
                                                                              \
      } else {                                                                \
                                                                              \
        break;                                                                \
                                                                              \
      }                                                                       \
                                                                              \
    } while (1);                                                              \
                                                                              \
                                                                              \
                                                                              \
  } while (0)

#define ck_read(fd, buf, len, fn)                              \
  do {                                                         \
                                                               \
    s32 _len = (s32)(len);                                     \
    s32 _res = read(fd, buf, _len);                            \
    if (_res != _len) RPFATAL(_res, "Short read from %s", fn); \
                                                               \
  } while (0)

#endif                                                   /* ! _HAVE_DEBUG_H */

