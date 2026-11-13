#define _GNU_SOURCE
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

static unsigned char alternate_stack[65536];

static void trace_fault(int number, siginfo_t *info, void *context) {
    (void)info;
    (void)context;
    void *frames[64];
    const char label[] = "KEYLESS_SIGSEGV\n";
    ssize_t written = write(STDERR_FILENO, label, sizeof(label) - 1);
    (void)written;
    int count = backtrace(frames, 64);
    backtrace_symbols_fd(frames, count, STDERR_FILENO);
    _exit(128 + number);
}

__attribute__((constructor)) static void install_trace(void) {
    void *warmup[1];
    (void)backtrace(warmup, 1);
    stack_t stack = {.ss_sp = alternate_stack, .ss_size = sizeof(alternate_stack)};
    if (sigaltstack(&stack, 0) != 0) {
        _exit(127);
    }
    struct sigaction action = {0};
    action.sa_sigaction = trace_fault;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, 0) != 0) {
        _exit(127);
    }
}
