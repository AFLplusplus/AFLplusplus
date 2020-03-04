#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/time.h>

#include "types.h"
#include "list.h"

typedef struct timer_event {

  u64 start_time;
  u64 end_time;
  void *data;
  void (*callback)(u64 start_time, u64 end_time, void *data);

} timer_event_t;

static list_t timer_events = {0};
static u64 next_end_time = 0;
static struct itimerval it;

/* Get unix time in milliseconds */

u64 get_cur_time(void) {

  //TODO:Remove dupes of this function

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

static void handle_timeout(int signum);

static void set_alarm_kickoff(u64 alarm_time) {

  struct sigaction sa = {0};
  sa.sa_handler = handle_timeout;
  sa.sa_flags = SA_RESTART;
  sigaction(SIGALRM, &sa, NULL);

  next_end_time = alarm_time;
  s64 millis = alarm_time - get_cur_time();
  if (millis < 0) millis = 1; // We may have waited too long :)

  it.it_value.tv_sec = millis / 1000;
  it.it_value.tv_usec = (millis % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

}

static void handle_timeout(int signum) {

  u64 cur_time = get_cur_time();
  next_end_time = 0;

  LIST_FOREACH(&timer_events, timer_event_t, {

    if (el->end_time <= cur_time) {

      el->callback(el->start_time, el->end_time, el->data);
      LIST_REMOVE_CURRENT_EL_IN_FOREACH();
      free(el);

    } else {

      if (!next_end_time || next_end_time > el->end_time) {
        next_end_time = el->end_time;
      }

    }

  });

  if (next_end_time) set_alarm_kickoff(next_end_time);

}

timer_event_t *timer_start(u64 millis, void (*callback)(u64 start_time, u64 end_time, void *data)) {

  /* add us to timeout list */

  timer_event_t *event = calloc(1, sizeof(timer_event_t));
  if (!event) FATAL("Failed to allocate timer event");
  event->callback = callback;
  event->start_time = get_cur_time();
  event->end_time = event->start_time + millis;

  list_append(&timer_events, event);

  /* set new timeout if not running or we are shorter than previous timouts */

  if (!next_end_time || next_end_time > event->end_time) set_alarm_kickoff(event->end_time);

  return event;

}

void timer_cancel(timer_event_t *event) {

  /* Could reschedule the alarm if needed, 
       but this way it triggers and resets anwyay */

  list_remove(&timer_events, event);
  free(event);

}

volatile u64 counter = 0;

void counter_inc() {
  printf("inc\n");
  counter++;
}

list_t testlist = {0};

int main(int argc, char **argv) {

  u64 c2;


  for (c2 = 0; c2 < 77; c2 ++) {

    list_append(&testlist, (void *)c2);

  }

  list_remove(&testlist, (void *)55);
  list_remove(&testlist, (void *)72);
  list_append(&testlist, (void *)88);
  list_append(&testlist, (void *)99);
  list_remove(&testlist, (void *)0);

  timer_start(1000, counter_inc);
  timer_event_t *cancelme = timer_start(2000, counter_inc);
  timer_start(3000, counter_inc);
  timer_start(1100, counter_inc);
  timer_cancel(cancelme);
  

  while(counter < 3) {

    c2 += counter;

  }

  printf("\n");
  LIST_FOREACH(&testlist, void, {
    printf("%d ", (int)el);
  })

  printf(" contain 0: %d", list_contains(&testlist, (void *)0));
  printf(" contain 1: %d", list_contains(&testlist, (void *)1));

}