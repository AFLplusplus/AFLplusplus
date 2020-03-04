#ifndef AFL_LIST
#define AFL_LIST

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "debug.h"

#define LIST_PREALLOC (64)  /* How many elements to allocate before malloc is needed */

typedef enum el_status {
  EL_UNUSED = 0,
  EL_USED,
  EL_ALLOCATED
} el_status_t;

typedef struct list_element {

  el_status_t status;
  struct list_element *prev;
  struct list_element *next;
  void *data;

} element_t;

typedef struct list {

  u32 child_elements_used;
  element_t child_elements[LIST_PREALLOC];

} list_t;

static inline element_t *get_head(list_t *list) {

  return &list->child_elements[0];

}

static element_t *list_alloc_el(list_t *list) {

  element_t *el = NULL;

  if (list->child_elements_used == LIST_PREALLOC) {

    el = calloc(1, sizeof(element_t));
    el->status = EL_ALLOCATED;
    return el;

  } else {

    /* Find one of our preallocated elements */
    u32 i;
    /* Start with 1 as 0 is HEAD */
    for (i = 1; i < LIST_PREALLOC; i++) { 

      el = &list->child_elements[i];
      if (el->status == EL_UNUSED) {

        list->child_elements_used++;
        el->status = EL_USED;
        return el;

      }
    }
  }

  FATAL("BUG in list.h -> no element found or allocated!");
  return el;

}

static void list_free_el(list_t *list, element_t *el) {

  if (el->status == EL_ALLOCATED) {

    free(el);

  } else {

    --list->child_elements_used;
    el->status = EL_UNUSED;

  }
}

static void list_append(list_t *list, void *el) {

  element_t *head = get_head(list);
  if (!head->next) {

    /* initialize */

    memset(list, 0, sizeof(list_t));
    head->next = head->prev = head;
    list->child_elements_used = 1;

  }

  element_t *el_box = list_alloc_el(list);
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

#define LIST_FOREACH(list, type, block) do { \
  list_t *li = (list);                       \
  element_t *head = get_head((li));          \
  element_t *el_box = (head)->next;          \
  /* printf("List access from %x (next = %x)"\
             "\n", (head), (head)->next); */ \
  if (!el_box)                               \
    FATAL("foreach over uninitialized list");\
  while(el_box != head) {                    \
    type *el = (type *)((el_box)->data);     \
    /* get next so el_box can be unlinked */ \
    element_t *next = el_box->next;          \
    {block};                                 \
    el_box = next;                           \
  }                                          \
} while(0);

/* In foreach: remove the current el from the list */

#define LIST_REMOVE_CURRENT_EL_IN_FOREACH() do { \
    el_box->prev->next = next;                   \
    el_box->next->prev = el_box->prev;           \
    list_free_el(li, el_box);                    \
} while(0);

/* Same as foreach, but will clear list in the process */

#define LIST_FOREACH_CLEAR(list, type, block) do { \
  LIST_FOREACH((list), type, {                     \
    {block};                                       \
    LIST_REMOVE_CURRENT_EL_IN_FOREACH();           \
  });                                              \
} while(0);

/* remove an item from the list */

static void list_remove(list_t *list, void *remove_me) {

  LIST_FOREACH(list, void, {
    if (el == remove_me) {
      el_box->prev->next = el_box->next;
      el_box->next->prev = el_box->prev;
      el_box->data = NULL;
      list_free_el(list, el_box);
      return;
    }
  });

  FATAL ("List item to be removed not in list");

}

/* Returns true if el is in list */

static bool list_contains(list_t *list, void *contains_me) {

  LIST_FOREACH(list, void, {
    if (el == contains_me) return true;
  });

  return false;

}

#endif