#ifndef AFL_LIST
#define AFL_LIST

#include <stdio.h>
#include <stdbool.h>

#include "debug.h"

typedef struct list {

  struct list *prev;
  struct list *next;
  void *data;

} list_t;

static void list_append(list_t *head, void *el) {

  if (!head->next) {

    /* initialize */
    head->next = head->prev = head;

  }

  list_t *el_box = calloc(1, sizeof(list_t));
  if (!el_box) FATAL("failed to allocate list element");
  el_box->data = el;
  el_box->next = head;
  el_box->prev = head->prev;
  head->prev->next = el_box;
  head->prev = el_box;

}

/* Simple foreach. 
   Pointer to the current element is in `el`,
   casted to (a pointer) of the given `type`.
   A return from this block will return from calling func.
*/

#define LIST_FOREACH(head, type, block) do { \
  list_t *el_box = (head)->next;             \
  /* printf("List access from %x (next = %x)"\
             "\n", (head), (head)->next); */ \
  if (!el_box)                               \
    FATAL("foreach over uninitialized list");\
  while(el_box != head) {                    \
    type *el = (type *)((el_box)->data);     \
    /* get next so el_box can be unlinked */ \
    list_t *next = el_box->next;             \
    {block};                                 \
    el_box = next;                           \
  }                                          \
} while(0);

/* In foreach: remove the current el from the list */

#define LIST_REMOVE_CURRENT_EL_IN_FOREACH() do {   \
    el_box->prev->next = next;                     \
    el_box->next->prev = el_box->prev;             \
    free(el_box);                                  \
} while(0);

/* Same as foreach, but will clear list in the process */

#define LIST_FOREACH_CLEAR(head, type, block) do { \
  LIST_FOREACH((head), type, {                     \
    {block};                                       \
    LIST_REMOVE_CURRENT_EL_IN_FOREACH();           \
  });                                              \
} while(0);

/* remove an item from the list */

static void list_remove(list_t *head, void *remove_me) {

  LIST_FOREACH(head, void, {
    if (el == remove_me) {
      el_box->prev->next = el_box->next;
      el_box->next->prev = el_box->prev;
      el_box->data = NULL;
      free(el_box);
      return;
    }
  });

  FATAL ("List item to be removed not in list");

}

/* Returns true if el is in list */

static bool list_contains(list_t *head, void *contains_me) {

  LIST_FOREACH(head, void, {
    if (el == contains_me) return true;
  });

  return false;

}

#endif