#ifndef _GRAMFUZZ_H

#define _GRAMFUZZ_H

#include <json-c/json.h>
#include <unistd.h>
#include "hashmap.h"
#include "uthash.h"
#include "utarray.h"

#define INIT_INPUTS 100  // No. of initial inputs to be generated

// Set this as `numstates` + 1 where `numstates` is retrieved from gen automata
// json #define STATES 63

#define INIT_SIZE 100  // Initial size of the dynamic array holding the input

#define SPLICE_CORPUS 10000
#define RECUR_THRESHOLD 6
#define SIZE_THRESHOLD 2048

#define FLUSH_INTERVAL \
  3600  // Inputs that gave new coverage will be dumped every FLUSH_INTERVAL
        // seconds

afl_state_t *global_afl;

typedef struct trigger {

  char * id;
  int    dest;
  char * term;
  size_t term_len;

} trigger;

typedef struct state {

  int      state_name;   // Integer State name
  int      trigger_len;  // Number of triggers associated with this state
  trigger *ptr;          // Pointer to beginning of the list of triggers

} state;

typedef struct terminal {

  int    state;
  int    trigger_idx;
  size_t symbol_len;
  char * symbol;

} terminal;

typedef struct buckethash {

  int freq;

} buckethash;

int init_state;
int curr_state;
int final_state;
int numstates;

/*****************
/ DYNAMIC ARRAY FOR WALKS
*****************/

typedef struct {

  size_t    used;
  size_t    size;
  size_t    inputlen;
  terminal *start;

} Array;

/*****************
/ DYNAMIC ARRAY FOR STATEMAPS/RECURSION MAPS
*****************/

typedef struct {

  int *  array;
  size_t used;
  size_t size;

} IdxMap;

typedef struct {

  UT_array *nums;

} IdxMap_new;

typedef struct {

  IdxMap_new *idxmap;
  UT_array ** recurIdx;

} Get_Dupes_Ret;

/* Candidate Struct */
typedef struct {

  Array *     walk;
  IdxMap_new *statemap;

} Candidate;

/* Splice Mutation helpers*/
typedef struct {

  Candidate *splice_cand;
  int        idx;

} SpliceCand;

typedef struct {

  SpliceCand *start;
  size_t      used;
  size_t      size;

} SpliceCandArray;

// Initialize dynamic array for potential splice points
SpliceCand potential[SPLICE_CORPUS];

typedef struct {

  int orig_idx;
  int splice_idx;

} intpair_t;

// Initialize dynamic array for potential splice points
// SpliceCand potential[SPLICE_CORPUS];
// IdxMap_new* rcuridx[STATES];

/* Prototypes*/
Array *    slice(Array *, int);
state *    create_pda(u8 *);
Array *    gen_input(state *, Array *);
Array *    gen_input_count(state *, Array *, int *);
int        updatebucket(map_t, int);
void       itoa(int, char *, int);
void       strrreverse(char *, char *);
void       dbg_hashmap(map_t);
void       print_repr(Array *, char *);
int        isSatisfied(map_t);
char *     get_state(char *);
Candidate *gen_candidate(Array *);

Array *spliceGF(Array *, Array *, int);
Array *performSpliceOne(Array *, IdxMap_new *, Array *);
/* Mutation Methods*/
Array *    performRandomMutation(state *, Array *);
Array *    performRandomMutationCount(state *, Array *, int *);
Array *    performSpliceMutationBench(state *, Array *, Candidate **);
UT_array **get_dupes(Array *, int *);
Array *    doMult(Array *, UT_array **, int);
Array *    doMultBench(Array *, UT_array **, int);

/* Benchmarks*/
void SpaceBenchmark(char *);
void GenInputBenchmark(char *, char *);
void RandomMutationBenchmark(char *, char *);
void MutationAggrBenchmark(char *, char *);
void SpliceMutationBenchmark(char *, char *);
void SpliceMutationBenchmarkOne(char *, char *);
void RandomRecursiveBenchmark(char *, char *);

/* Testers */
void SanityCheck(char *);

/*Helpers*/
void   initArray(Array *, size_t);
void   insertArray(Array *, int, char *, size_t, int);
void   freeArray(Array *);
void   initArrayIdx(IdxMap *, size_t);
void   insertArrayIdx(IdxMap *, int);
void   freeArrayIdx(IdxMap *);
void   initArraySplice(SpliceCandArray *, size_t);
void   insertArraySplice(SpliceCandArray *, Candidate *, int);
void   freeArraySplice(IdxMap *);
void   getTwoIndices(UT_array *, int, int *, int *);
void   swap(int *, int *);
Array *slice_inverse(Array *, int);
void   concatPrefixFeature(Array *, Array *);
void   concatPrefixFeatureBench(Array *, Array *);
Array *carve(Array *, int, int);
int    fact(int);

void                add_to_corpus(struct json_object *, Array *);
struct json_object *term_to_json(terminal *);

/* Gramatron specific prototypes */
u8 *   unparse_walk(Array *);
Array *performSpliceGF(state *, Array *, afl_state_t *);
void   dump_input(u8 *, char *, int *);
void   write_input(Array *, u8 *);
Array *read_input(state *, u8 *);
state *pda;

// // AFL-specific struct
// typedef uint8_t  u8;
// typedef uint16_t u16;
// typedef uint32_t u32;
// #ifdef __x86_64__
// typedef unsigned long long u64;
// #else
// typedef uint64_t u64;
// #endif                                                    /* ^__x86_64__ */
//
// struct queue_entry {

//   Array* walk;                           /* Pointer to the automaton walk*/
//   u32 walk_len;                          /* Number of tokens in the input*/
//   Candidate* cand;                     /* Preprocessed info about the
//   candidate to allow for faster mutations*/
//
//   u8* fname;                          /* File name for the test case      */
//   u32 len;                            /* Input length                     */
//   UT_array** recur_idx;               /* Keeps track of recursive feature
//   indices*/
//
//   u32 recur_len;                      /* The number of recursive features*/
//
//   u8  cal_failed,                     /* Calibration failed?              */
//       trim_done,                      /* Trimmed?                         */
//       was_fuzzed,                     /* Had any fuzzing done yet?        */
//       passed_det,                     /* Deterministic stages passed?     */
//       has_new_cov,                    /* Triggers new coverage?           */
//       var_behavior,                   /* Variable behavior?               */
//       favored,                        /* Currently favored?               */
//       fs_redundant;                   /* Marked as redundant in the fs?   */
//
//   u32 bitmap_size,                    /* Number of bits set in bitmap     */
//       exec_cksum;                     /* Checksum of the execution trace  */
//
//   u64 exec_us,                        /* Execution time (us)              */
//       handicap,                       /* Number of queue cycles behind    */
//       depth;                          /* Path depth                       */
//
//   u8* trace_mini;                     /* Trace bytes, if kept             */
//   u32 tc_ref;                         /* Trace bytes ref count            */
//
//   struct queue_entry *next,           /* Next element, if any             */
//                      *next_100;       /* 100 elements ahead               */
//
// };

#endif

