#include "frida-gumjs.h"

#include "debug.h"

#include "js.h"
#include "util.h"

static char *             js_script = NULL;
gboolean                  js_done = FALSE;
js_api_stalker_callback_t js_user_callback = NULL;

static gchar *           filename = "afl.js";
static gchar *           contents;
static GumScriptBackend *backend;
static GCancellable *    cancellable = NULL;
static GError *          error = NULL;
static GumScript *       script;

static void js_msg(GumScript *script, const gchar *message, GBytes *data,
                   gpointer user_data) {

  UNUSED_PARAMETER(script);
  UNUSED_PARAMETER(data);
  UNUSED_PARAMETER(user_data);
  OKF("%s", message);

}

void js_config(void) {

  js_script = getenv("AFL_FRIDA_JS_SCRIPT");

}

static gchar *js_get_script() {

  gsize length;
  if (js_script != NULL) { filename = js_script; }

  filename = g_canonicalize_filename(filename, g_get_current_dir());

  if (!g_file_get_contents(filename, &contents, &length, NULL)) {

    if (js_script == NULL) {

      return NULL;

    } else {

      FATAL("Could not load script file: %s", filename);

    }

  } else {

    OKF("Loaded AFL script: %s, %" G_GSIZE_MODIFIER "d bytes", filename,
        length);

    gchar *source = g_malloc0(api_js_len + length + 1);
    memcpy(source, api_js, api_js_len);
    memcpy(&source[api_js_len], contents, length);

    return source;

  }

}

static void js_print_script(gchar *source) {

  gchar **split = g_strsplit(source, "\n", 0);

  for (size_t i = 0; split[i] != NULL; i++) {

    OKF("%3" G_GSIZE_MODIFIER "d. %s", i + 1, split[i]);

  }

  g_strfreev(split);

}

void js_start(void) {

  GMainContext *context;

  gchar *source = js_get_script();
  if (source == NULL) { return; }
  js_print_script(source);

  backend = gum_script_backend_obtain_qjs();

  script = gum_script_backend_create_sync(backend, "example", source,
                                          cancellable, &error);

  if (error != NULL) {

    g_printerr("%s\n", error->message);
    FATAL("Error processing script");

  }

  gum_script_set_message_handler(script, js_msg, NULL, NULL);

  gum_script_load_sync(script, cancellable);

  context = g_main_context_get_thread_default();
  while (g_main_context_pending(context))
    g_main_context_iteration(context, FALSE);

  if (!js_done) { FATAL("Script didn't call Afl.done()"); }

}

gboolean js_stalker_callback(const cs_insn *insn, gboolean begin,
                             gboolean excluded, GumStalkerOutput *output) {

  if (js_user_callback == NULL) { return TRUE; }
  return js_user_callback(insn, begin, excluded, output);

}

