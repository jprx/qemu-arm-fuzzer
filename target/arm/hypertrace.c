#include "hypercall.h"
#include "hypertrace.h"
#include <sys/mman.h>

static uint64_t *cursor = NULL;
static uint64_t *tracebuf = NULL;
static int tracing_enabled = false;
static uint64_t last_trace_len = 0;

void start_hypertrace(void) {
    if (NULL == tracebuf) {
        tracebuf = mmap(NULL, 0x1000000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

        if (MAP_FAILED == tracebuf) {
            qemu_log("FAILED TO MMAP\n");
            exit(0);
        }
        else {
            qemu_log("mmap success! tracebuf is at %p\n", tracebuf);
        }
    }

    cursor = tracebuf;
    *cursor = 0;
    tracing_enabled = true;
}

void stop_hypertrace(void) {
    tracing_enabled = false;
    uint64_t trace_len = cursor - tracebuf;
    if (trace_len != last_trace_len) {
        last_trace_len = trace_len;
        qemu_log("Unique fuzz case found!\n");
    }
    else {
        qemu_log("Non-unique fuzz case\n");
    }
    qemu_log("Hypertrace len: %lx\n", cursor - tracebuf);
    qemu_log("Hypertrace log:\n");
    uint64_t *tmp_cursor = tracebuf;
    while (*tmp_cursor) {
        qemu_log("%lx\n", *tmp_cursor);
        tmp_cursor++;
    }
}

void submit_pc(uint64_t pc_val) {
    if (tracing_enabled) {
        *cursor = pc_val;
        cursor++;
        *cursor = 0;
    }
}
