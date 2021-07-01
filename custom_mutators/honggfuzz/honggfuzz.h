/*
 *
 * honggfuzz - core structures and macros
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#ifndef _HF_HONGGFUZZ_H_
#define _HF_HONGGFUZZ_H_

#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <time.h>

#include "libhfcommon/util.h"

#define PROG_NAME    "honggfuzz"
#define PROG_VERSION "2.4"

/* Name of the template which will be replaced with the proper name of the file */
#define _HF_FILE_PLACEHOLDER "___FILE___"

/* Default name of the report created with some architectures */
#define _HF_REPORT_FILE "HONGGFUZZ.REPORT.TXT"

/* Default stack-size of created threads. */
#define _HF_PTHREAD_STACKSIZE (1024ULL * 1024ULL * 2ULL) /* 2MB */

/* Name of envvar which indicates sequential number of fuzzer */
#define _HF_THREAD_NO_ENV "HFUZZ_THREAD_NO"

/* Name of envvar which indicates that the netDriver should be used */
#define _HF_THREAD_NETDRIVER_ENV "HFUZZ_USE_NETDRIVER"

/* Name of envvar which indicates honggfuzz's log level in use */
#define _HF_LOG_LEVEL_ENV "HFUZZ_LOG_LEVEL"

/* Number of crash verifier iterations before tag crash as stable */
#define _HF_VERIFIER_ITER 5

/* Size (in bytes) for report data to be stored in stack before written to file */
#define _HF_REPORT_SIZE 32768

/* Perf bitmap size */
#define _HF_PERF_BITMAP_SIZE_16M   (1024U * 1024U * 16U)
#define _HF_PERF_BITMAP_BITSZ_MASK 0x7FFFFFFULL
/* Maximum number of PC guards (=trace-pc-guard) we support */
#define _HF_PC_GUARD_MAX (1024ULL * 1024ULL * 64ULL)

/* Maximum size of the input file in bytes (1 MiB) */
#define _HF_INPUT_MAX_SIZE (1024ULL * 1024ULL)

/* Default maximum size of produced inputs */
#define _HF_INPUT_DEFAULT_SIZE (1024ULL * 8)

/* Per-thread bitmap */
#define _HF_PERTHREAD_BITMAP_FD 1018
/* FD used to report back used int/str constants from the fuzzed process */
#define _HF_CMP_BITMAP_FD 1019
/* FD used to log inside the child process */
#define _HF_LOG_FD 1020
/* FD used to represent the input file */
#define _HF_INPUT_FD 1021
/* FD used to pass coverage feedback from the fuzzed process */
#define _HF_COV_BITMAP_FD 1022
#define _HF_BITMAP_FD     _HF_COV_BITMAP_FD /* Old name for _HF_COV_BITMAP_FD */
/* FD used to pass data to a persistent process */
#define _HF_PERSISTENT_FD 1023

/* Input file as a string */
#define _HF_INPUT_FILE_PATH "/dev/fd/" HF_XSTR(_HF_INPUT_FD)

/* Maximum number of supported execve() args */
#define _HF_ARGS_MAX 2048

/* Message indicating that the fuzzed process is ready for new data */
static const uint8_t HFReadyTag = 'R';

/* Maximum number of active fuzzing threads */
#define _HF_THREAD_MAX 1024U

/* Persistent-binary signature - if found within file, it means it's a persistent mode binary */
#define _HF_PERSISTENT_SIG "\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"
/* HF NetDriver signature - if found within file, it means it's a NetDriver-based binary */
#define _HF_NETDRIVER_SIG "\x01_LIBHFUZZ_NETDRIVER_BINARY_SIGNATURE_\x02\xFF"

/* printf() nonmonetary separator. According to MacOSX's man it's supported there as well */
#define _HF_NONMON_SEP "'"

typedef enum {
    _HF_DYNFILE_NONE         = 0x0,
    _HF_DYNFILE_INSTR_COUNT  = 0x1,
    _HF_DYNFILE_BRANCH_COUNT = 0x2,
    _HF_DYNFILE_BTS_EDGE     = 0x10,
    _HF_DYNFILE_IPT_BLOCK    = 0x20,
    _HF_DYNFILE_SOFT         = 0x40,
} dynFileMethod_t;

typedef struct {
    uint64_t cpuInstrCnt;
    uint64_t cpuBranchCnt;
    uint64_t bbCnt;
    uint64_t newBBCnt;
    uint64_t softCntPc;
    uint64_t softCntEdge;
    uint64_t softCntCmp;
} hwcnt_t;

typedef enum {
    _HF_STATE_UNSET = 0,
    _HF_STATE_STATIC,
    _HF_STATE_DYNAMIC_DRY_RUN,
    _HF_STATE_DYNAMIC_MAIN,
    _HF_STATE_DYNAMIC_MINIMIZE,
} fuzzState_t;

typedef enum {
    HF_MAYBE = -1,
    HF_NO    = 0,
    HF_YES   = 1,
} tristate_t;

struct _dynfile_t {
    size_t             size;
    uint64_t           cov[4];
    size_t             idx;
    int                fd;
    uint64_t           timeExecUSecs;
    char               path[PATH_MAX];
    struct _dynfile_t* src;
    uint32_t           refs;
    uint8_t*           data;
    TAILQ_ENTRY(_dynfile_t) pointers;
};

typedef struct _dynfile_t dynfile_t;

struct strings_t {
    size_t len;
    TAILQ_ENTRY(strings_t) pointers;
    char s[];
};

typedef struct {
    uint8_t  pcGuardMap[_HF_PC_GUARD_MAX];
    uint8_t  bbMapPc[_HF_PERF_BITMAP_SIZE_16M];
    uint32_t bbMapCmp[_HF_PERF_BITMAP_SIZE_16M];
    uint64_t pidNewPC[_HF_THREAD_MAX];
    uint64_t pidNewEdge[_HF_THREAD_MAX];
    uint64_t pidNewCmp[_HF_THREAD_MAX];
    uint64_t guardNb;
    uint64_t pidTotalPC[_HF_THREAD_MAX];
    uint64_t pidTotalEdge[_HF_THREAD_MAX];
    uint64_t pidTotalCmp[_HF_THREAD_MAX];
} feedback_t;

typedef struct {
    uint32_t cnt;
    struct {
        uint8_t  val[32];
        uint32_t len;
    } valArr[1024 * 16];
} cmpfeedback_t;

typedef struct {
    struct {
        size_t    threadsMax;
        size_t    threadsFinished;
        uint32_t  threadsActiveCnt;
        pthread_t mainThread;
        pid_t     mainPid;
        pthread_t threads[_HF_THREAD_MAX];
    } threads;
    struct {
        const char* inputDir;
        const char* outputDir;
        DIR*        inputDirPtr;
        size_t      fileCnt;
        size_t      testedFileCnt;
        const char* fileExtn;
        size_t      maxFileSz;
        size_t      newUnitsAdded;
        char        workDir[PATH_MAX];
        const char* crashDir;
        const char* covDirNew;
        bool        saveUnique;
        bool        saveSmaller;
        size_t      dynfileqMaxSz;
        size_t      dynfileqCnt;
        dynfile_t*  dynfileqCurrent;
        dynfile_t*  dynfileq2Current;
        TAILQ_HEAD(dyns_t, _dynfile_t) dynfileq;
        bool exportFeedback;
    } io;
    struct {
        int                argc;
        const char* const* cmdline;
        bool               nullifyStdio;
        bool               fuzzStdin;
        const char*        externalCommand;
        const char*        postExternalCommand;
        const char*        feedbackMutateCommand;
        bool               netDriver;
        bool               persistent;
        uint64_t           asLimit;
        uint64_t           rssLimit;
        uint64_t           dataLimit;
        uint64_t           coreLimit;
        uint64_t           stackLimit;
        bool               clearEnv;
        char*              env_ptrs[128];
        char               env_vals[128][4096];
        sigset_t           waitSigSet;
    } exe;
    struct {
        time_t  timeStart;
        time_t  runEndTime;
        time_t  tmOut;
        time_t  lastCovUpdate;
        int64_t timeOfLongestUnitUSecs;
        bool    tmoutVTALRM;
    } timing;
    struct {
        struct {
            uint8_t val[512];
            size_t  len;
        } dictionary[8192];
        size_t      dictionaryCnt;
        const char* dictionaryFile;
        size_t      mutationsMax;
        unsigned    mutationsPerRun;
        size_t      maxInputSz;
    } mutate;
    struct {
        bool    useScreen;
        char    cmdline_txt[65];
        int64_t lastDisplayUSecs;
    } display;
    struct {
        bool        useVerifier;
        bool        exitUponCrash;
        uint8_t     exitCodeUponCrash;
        const char* reportFile;
        size_t      dynFileIterExpire;
        bool        only_printable;
        bool        minimize;
        bool        switchingToFDM;
    } cfg;
    struct {
        bool enable;
        bool del_report;
    } sanitizer;
    struct {
        fuzzState_t     state;
        feedback_t*     covFeedbackMap;
        int             covFeedbackFd;
        cmpfeedback_t*  cmpFeedbackMap;
        int             cmpFeedbackFd;
        bool            cmpFeedback;
        const char*     blocklistFile;
        uint64_t*       blocklist;
        size_t          blocklistCnt;
        bool            skipFeedbackOnTimeout;
        uint64_t        maxCov[4];
        dynFileMethod_t dynFileMethod;
        hwcnt_t         hwCnts;
    } feedback;
    struct {
        size_t mutationsCnt;
        size_t crashesCnt;
        size_t uniqueCrashesCnt;
        size_t verifiedCrashesCnt;
        size_t blCrashesCnt;
        size_t timeoutedCnt;
    } cnts;
    struct {
        bool enabled;
        int  serverSocket;
        int  clientSocket;
    } socketFuzzer;
    struct {
        pthread_rwlock_t dynfileq;
        pthread_mutex_t  feedback;
        pthread_mutex_t  report;
        pthread_mutex_t  state;
        pthread_mutex_t  input;
        pthread_mutex_t  timing;
    } mutex;

    /* For the Linux code */
    struct {
        int         exeFd;
        uint64_t    dynamicCutOffAddr;
        bool        disableRandomization;
        void*       ignoreAddr;
        const char* symsBlFile;
        char**      symsBl;
        size_t      symsBlCnt;
        const char* symsWlFile;
        char**      symsWl;
        size_t      symsWlCnt;
        uintptr_t   cloneFlags;
        tristate_t  useNetNs;
        bool        kernelOnly;
        bool        useClone;
    } arch_linux;
    /* For the NetBSD code */
    struct {
        void*       ignoreAddr;
        const char* symsBlFile;
        char**      symsBl;
        size_t      symsBlCnt;
        const char* symsWlFile;
        char**      symsWl;
        size_t      symsWlCnt;
    } arch_netbsd;
} honggfuzz_t;

typedef enum {
    _HF_RS_UNKNOWN                   = 0,
    _HF_RS_WAITING_FOR_INITIAL_READY = 1,
    _HF_RS_WAITING_FOR_READY         = 2,
    _HF_RS_SEND_DATA                 = 3,
} runState_t;

typedef struct {
    honggfuzz_t* global;
    pid_t        pid;
    int64_t      timeStartedUSecs;
    char         crashFileName[PATH_MAX];
    uint64_t     pc;
    uint64_t     backtrace;
    uint64_t     access;
    int          exception;
    char         report[_HF_REPORT_SIZE];
    bool         mainWorker;
    unsigned     mutationsPerRun;
    dynfile_t*   dynfile;
    bool         staticFileTryMore;
    uint32_t     fuzzNo;
    int          persistentSock;
    runState_t   runState;
    bool         tmOutSignaled;
    char*        args[_HF_ARGS_MAX + 1];
    int          perThreadCovFeedbackFd;
    unsigned     triesLeft;
    dynfile_t*   current;
#if !defined(_HF_ARCH_DARWIN)
    timer_t timerId;
#endif    // !defined(_HF_ARCH_DARWIN)
    hwcnt_t hwCnts;

    struct {
        /* For Linux code */
        uint8_t* perfMmapBuf;
        uint8_t* perfMmapAux;
        int      cpuInstrFd;
        int      cpuBranchFd;
        int      cpuIptBtsFd;
    } arch_linux;
} run_t;

#endif
