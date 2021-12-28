#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include "nyx.h"

/* this is our "bitmap" that is later shared with the fuzzer (you can also pass the pointer of the bitmap used by compile-time instrumentations in your target) */ 
uint8_t* trace_buffer[64*1024] = {0};

int main(int argc, char** argv){
	/* if you want to debug code running in Nyx, hprintf() is the way to go. 
	*  Long story short -- it's just a guest-to-hypervisor printf. Hence the name "hprintf" 
	*/
	hprintf("Agent test\n");

	/* Request information on available (host) capabilites (optional) */
	host_config_t host_config;
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
	hprintf("[capablities] host_config.bitmap_size: 0x%"PRIx64"\n", host_config.bitmap_size);
    hprintf("[capablities] host_config.ijon_bitmap_size: 0x%"PRIx64"\n", host_config.ijon_bitmap_size);
    hprintf("[capablities] host_config.payload_buffer_size: 0x%"PRIx64"x\n", host_config.payload_buffer_size);
	
	/* Submit agent configuration */
	memset(trace_buffer, 0, 64*1024); // makes sure that the bitmap buffer is already mapped into the guest's memory (alternatively you can use mlock) */
	agent_config_t agent_config = {0};
	agent_config.agent_timeout_detection = 0; 								/* timeout detection is implemented by the agent (currently not used) */
	agent_config.agent_tracing = 1;											/* set this flag to propagade that instrumentation-based fuzzing is availabe */
	agent_config.agent_ijon_tracing = 0; 									/* set this flag to propagade that IJON extension is implmented agent-wise */
	agent_config.trace_buffer_vaddr = (uintptr_t)trace_buffer;				/* trace "bitmap" pointer - required for instrumentation-only fuzzing */
	agent_config.ijon_trace_buffer_vaddr = (uintptr_t)NULL;					/* "IJON" buffer pointer */
    agent_config.agent_non_reload_mode = 1;									/* non-reload mode is supported (usually because the agent implements a fork-server; currently not used) */
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

	/* Tell hypervisor the virtual address of the payload (input) buffer (call mlock to ensure that this buffer stays in the guest's memory)*/
	kAFL_payload* payload_buffer = mmap((void*)0x4000000ULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	mlock(payload_buffer, (size_t)PAYLOAD_SIZE);
	memset(payload_buffer, 0, PAYLOAD_SIZE);
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);
	hprintf("[init] payload buffer is mapped at %p\n", payload_buffer);

	/* the main fuzzing loop */
	while(1){

		/* Creates a root snapshot on first execution. Also we requested the next input with this hypercall */
		kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0); // root snapshot <--

#ifdef DEBUG
		hprintf("Size: %ld Data: %x %x %x %x\n", payload_buffer->size,
								payload_buffer->data[4],
								payload_buffer->data[5],
								payload_buffer->data[6],
								payload_buffer->data[7]
								);
#endif

		uint32_t len = payload_buffer->size;

		/* set a byte to make AFL++ happy (otherwise the fuzzer might refuse to start fuzzing at all) */
		((uint8_t*)trace_buffer)[0] = 0x1;

		if (len >= 4){
			/* set a byte in the bitmap to guide your fuzzer */
			((uint8_t*)trace_buffer)[0] = 0x1;
			if (payload_buffer->data[0] == '!'){
				((uint8_t*)trace_buffer)[1] = 0x1;
				if (payload_buffer->data[1] == 'N'){
					((uint8_t*)trace_buffer)[2] = 0x1;
					if (payload_buffer->data[2] == 'Y'){
						((uint8_t*)trace_buffer)[3] = 0x1;
						if (payload_buffer->data[3] == 'X'){
							((uint8_t*)trace_buffer)[4] = 0x1;
							/* Notifiy the hypervisor and the fuzzer that a "crash" has occured. Also a string is passed by this hypercall (this is currently not supported by AFL++-Nyx) */
							kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)"Something went wrong\n");
						}
					}
				}
			}
		}
		/* this hypercall is used to notify the hypervisor and the fuzzer that a single fuzzing "execution" has finished.
		 * If the reload-mode is enabled, we will jump back to our root snapshot. 
		 * Otherwise, the hypervisor passes control back to the guest once the bitmap buffer has been "processed" by the fuzzer.
		 */
		kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

		/* This shouldn't happen if you have enabled the reload mode */ 
		hprintf("Das sollte niemals passieren :)\n");
	}


	return 0;
}
