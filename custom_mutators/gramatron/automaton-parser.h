#ifndef _AUTOMATON_PARSER_H
#define _AUTOMATON_PARSER_H

#define NUMINPUTS 500
#define MAX_PROGRAM_LENGTH 20000
#define MAX_PROGRAM_WALK_LENGTH 5000
#define MAX_TERMINAL_NUMS 5000
#define MAX_TERMINAL_LENGTH 1000
#define MAX_PROGRAM_NAME_LENGTH 5000

#include "gramfuzz.h"

// represents an edge in the FSA
struct terminal_meta {

  int state_name;
  int trigger_idx;
  int dest;

} ;

// represents a set of edges 
struct terminal_arr {

  struct terminal_meta* start;
  size_t len;

} ;

// essentially a string array
struct symbols_arr {
  char** symbols_arr;
  size_t len;
} ;

struct symbols_arr* symbols; // symbols contain all the symbols in the language
map_t pda_map; // a map that maps each symbol in the language to a set of edges 
struct symbols_arr* first_chars; // an array of first characters, only temperary array
map_t first_char_to_symbols_map; // a map that maps each first character to a set of symbols (the symbols are sorted in descending order)



// freeing terminal arrays
int free_terminal_arr(any_t placeholder, any_t item);

// return a map that maps each symbol in the language to a set of edges 
// populate symbols_arr with all the symbols in the language
map_t create_pda_hashmap(state* pda, struct symbols_arr* symbols_arr);

// print the string array
void print_symbols_arr(struct symbols_arr* arr);

// free hashmap
// the function pointer contains function to free the values in the hashmap
void free_hashmap(map_t m, int (*f)(any_t, any_t));

// free string array
int free_array_of_chars(any_t placeholder, any_t item);

// free the pda
void free_pda(state* pda);

// create a string array
struct symbols_arr* create_array_of_chars();

map_t create_first_char_to_symbols_hashmap(struct symbols_arr *symbols, struct symbols_arr *first_chars);

// return the automaton represented by the seed
Array* automaton_parser(const uint8_t *seed_fn);

int add_element_to_symbols_arr(struct symbols_arr* symbols_arr, char* symbol, size_t symbol_len);


#endif