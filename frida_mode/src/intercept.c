#include "frida-gumjs.h"

#include "debug.h"

#include "intercept.h"

void intercept_hook(void *address, gpointer replacement, gpointer user_data) {

  GumInterceptor *interceptor = gum_interceptor_obtain();
  gum_interceptor_begin_transaction(interceptor);
  GumReplaceReturn ret =
      gum_interceptor_replace(interceptor, address, replacement, user_data);
  if (ret != GUM_REPLACE_OK) { FATAL("gum_interceptor_attach: %d", ret); }
  gum_interceptor_end_transaction(interceptor);

}

void intercept_unhook(void *address) {

  GumInterceptor *interceptor = gum_interceptor_obtain();

  gum_interceptor_begin_transaction(interceptor);
  gum_interceptor_revert(interceptor, address);
  gum_interceptor_end_transaction(interceptor);
  gum_interceptor_flush(interceptor);

}

void intercept_unhook_self(void) {

  GumInvocationContext *ctx = gum_interceptor_get_current_invocation();
  intercept_unhook(ctx->function);

}

