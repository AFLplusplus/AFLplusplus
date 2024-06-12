#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "types.h"
#define TABLE_SIZE 10007  // Use a prime number for better distribution

typedef struct HashNode {

  uint64_t         key;
  struct HashNode *next;

} HashNode;

typedef struct HashMap {

  HashNode **table;

} HashMap;

static HashMap *_hashmap;

void hashmap_reset() {

  if (unlikely(!_hashmap)) {

    _hashmap = (HashMap *)malloc(sizeof(HashMap));
    _hashmap->table = (HashNode **)malloc(sizeof(HashNode *) * TABLE_SIZE);
    memset((char *)_hashmap->table, 0, sizeof(HashNode *) * TABLE_SIZE);

  } else {

    for (int i = 0; i < TABLE_SIZE; i++) {

      HashNode *node = _hashmap->table[i];
      while (node) {

        HashNode *temp = node;
        node = node->next;
        free(temp);

      }

    }

    memset((char *)_hashmap->table, 0, sizeof(HashNode *) * TABLE_SIZE);

  }

}

static inline unsigned int hash(uint64_t key) {

  return key % TABLE_SIZE;

}

// type must be below 8
bool hashmap_search_and_add(uint8_t type, uint64_t key) {

  if (unlikely(type >= 8)) return false;
  uint64_t     val = (key & 0xf8ffffffffffffff) + ((uint64_t)type << 56);
  unsigned int index = hash(val);
  HashNode    *node = _hashmap->table[index];
  while (node) {

    if (node->key == val) return true;
    node = node->next;

  }

  // not found so add it
  node = (HashNode *)malloc(sizeof(HashNode));
  node->key = val;
  node->next = _hashmap->table[index];
  _hashmap->table[index] = node;

  return false;

}

// type must be below 8
bool hashmap_search_and_add_ptr(uint8_t type, u8 *key) {

  if (unlikely(type >= 8)) return false;
  uint64_t key_t = 0;
  memcpy(((char *)key_t) + (7 - type), key, type + 1);
  return hashmap_search_and_add(type, key_t);

}

/* below is not used */

void hashmap_insert(uint64_t key) {

  unsigned int index = hash(key);
  HashNode    *node = (HashNode *)malloc(sizeof(HashNode));
  node->key = key;
  node->next = _hashmap->table[index];
  _hashmap->table[index] = node;

}

bool hashmap_search(uint64_t key) {

  unsigned int index = hash(key);
  HashNode    *node = _hashmap->table[index];
  while (node) {

    if (node->key == key) return true;
    node = node->next;

  }

  return false;

}

void delete(uint64_t key) {

  unsigned int index = hash(key);
  HashNode    *prev = NULL, *node = _hashmap->table[index];
  while (node) {

    if (node->key == key) {

      if (prev)
        prev->next = node->next;
      else
        _hashmap->table[index] = node->next;
      free(node);
      return;

    }

    prev = node;
    node = node->next;

  }

}

void freeHashMap(HashMap *map) {

  free(_hashmap->table);
  free(map);

}

