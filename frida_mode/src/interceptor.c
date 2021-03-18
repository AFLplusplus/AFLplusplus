#include "frida-gum.h"
#include "debug.h"

#include "interceptor.h"

void intercept(void *address, gpointer replacement, gpointer user_data) {

  GumInterceptor *interceptor = gum_interceptor_obtain();
  gum_interceptor_begin_transaction(interceptor);
  GumReplaceReturn ret =
      gum_interceptor_replace(interceptor, address, replacement, user_data);
  if (ret != GUM_ATTACH_OK) { FATAL("gum_interceptor_attach: %d", ret); }
  gum_interceptor_end_transaction(interceptor);

}

