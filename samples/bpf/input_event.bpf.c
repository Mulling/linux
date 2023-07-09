#include "vmlinux.h"
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define KEY_LEFTCTRL 29
#define KEY_CAPSLOCK 58


struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, unsigned int);
	__uint(max_entries, 1024);
} queue SEC(".maps");

extern void bpf_input_event(unsigned int type, unsigned int code,
			    unsigned int value) __ksym;

// extern int *bpf_test(struct bpf_input_ctx *ctx) __ksym;

extern int *bpf_test(struct bpf_input_ctx *ctx, unsigned int offset,
		     const size_t __sz) __ksym;

SEC("fmod_ret/input_event_bpf")
int BPF_PROG(bpf_input, unsigned int type, unsigned int code,
	     unsigned int value, struct bpf_input_ctx *bctx)
{
	bpf_input_event(type, code, value);

	int *codep = bpf_test(bctx, 0, sizeof(int));

	if (!codep)
		return 0;

    if (code == KEY_CAPSLOCK) {
        codep[0] = KEY_LEFTCTRL;
    }

	bpf_map_push_elem(&queue, codep, BPF_EXIST);

	return 0;
};

char _license[] SEC("license") = "GPL";
