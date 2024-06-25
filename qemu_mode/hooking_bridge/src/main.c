#include <stdio.h>
#include <stdlib.h>
#include "common.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static void finish_cb(qemu_plugin_id_t id, void *userdata) {

  patch_finish_cb(userdata);

}

static void block_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {

  patch_block_trans_cb(tb);

}

static void vpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index) {

  patch_vpu_init_cb(vcpu_index);

}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc,
                        char **argv) {

  patch_init(argv[0]);
  qemu_plugin_register_vcpu_init_cb(id, vpu_init_cb);
  qemu_plugin_register_vcpu_tb_trans_cb(id, block_trans_cb);
  qemu_plugin_register_atexit_cb(id, finish_cb, NULL);
  return 0;

}

