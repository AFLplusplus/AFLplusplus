#ifndef COMMON_H
#define COMMON_H

#include <qemu/qemu-plugin.h>

void patch_finish_cb(void *userdata);
void patch_block_trans_cb(struct qemu_plugin_tb *tb);
void patch_vpu_init_cb(unsigned int vcpu_index);
void patch_init(char *hook_library);

#endif