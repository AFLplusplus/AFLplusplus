#include "frida-gum.h"

#include "debug.h"

#include "interceptor.h"

void intercept(void *address, gpointer replacement, gpointer user_data) {

  GumInterceptor *interceptor = gum_interceptor_obtain();
  gum_interceptor_begin_transaction(interceptor);
  GumReplaceReturn ret =
      gum_interceptor_replace(interceptor, address, replacement, user_data);
  if (ret != GUM_REPLACE_OK) { FATAL("gum_interceptor_attach: %d", ret); }
  gum_interceptor_end_transaction(interceptor);

}

void unintercept(void *address) {

  GumInterceptor *interceptor = gum_interceptor_obtain();

  gum_interceptor_begin_transaction(interceptor);
  gum_interceptor_revert(interceptor, address);
  gum_interceptor_end_transaction(interceptor);
  gum_interceptor_flush(interceptor);

}

void unintercept_self(void) {

  GumInvocationContext *ctx = gum_interceptor_get_current_invocation();
  unintercept(ctx->function);

}

