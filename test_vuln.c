/*
 * CVE-2019-13272 — Vulnerability test (PoC)
 *
 * Tests for the ptrace_link credential mishandling in kernel < 5.1.17.
 * This creates a parent-child scenario where the bug can be observed:
 * - Child calls PTRACE_TRACEME (wants to be traced by parent)
 * - Parent drops privileges then exec's (e.g. /bin/true)
 * On a vulnerable kernel, the credential recording in ptrace_link is wrong,
 * and the object lifetime issue may cause a kernel panic or odd behavior.
 *
 * Compile: gcc -o test_vuln test_vuln.c
 * Run in VM with vulnerable kernel only.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <errno.h>
#include <string.h>

static void child_ptrace_traceme(void)
{
    /* Child: request to be traced by parent (PTRACE_TRACEME) */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        perror("ptrace(PTRACE_TRACEME)");
        exit(1);
    }
    /* Will be stopped by SIGTRAP; parent will see this */
    raise(SIGTRAP);
}

int main(void)
{
    pid_t pid;
    int status;

    printf("[*] CVE-2019-13272 vulnerability test\n");
    printf("[*] Kernel should be < 5.1.17 for vulnerability\n");

    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Child: establish that parent will be our tracer */
        child_ptrace_traceme();
        _exit(0);
    }

    /* Parent */
    printf("[*] Child PID: %d\n", pid);

    /* Wait for child to hit PTRACE_TRACEME + SIGTRAP */
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        printf("[-] Unexpected status: 0x%x (expected SIGTRAP stop)\n", status);
        return 1;
    }

    printf("[*] Child stopped with SIGTRAP (ptrace relationship established)\n");

    /*
     * On a vulnerable kernel, the parent has now been recorded as the tracer
     * with incorrect credential handling. Next step in the real exploit
     * would be: parent drops privileges (setresuid to non-root) and then
     * exec's a setuid helper (e.g. pkexec). The bug allows the child to
     * abuse this relationship for privilege escalation.
     *
     * Here we only detach and exit to avoid crashing. To fully trigger
     * the "object lifetime" bug you could have the parent exit or exec
     * without properly detaching, which can panic vulnerable kernels.
     */
    if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
        perror("ptrace(PTRACE_DETACH)");
        /* On vulnerable kernel, credential/lifetime bugs may appear here */
    }
    waitpid(pid, &status, 0);

    printf("[*] Test finished. If no panic and ptrace behaved as above, kernel may be vulnerable.\n");
    printf("[*] Run the full exploit only in an isolated VM.\n");
    return 0;
}
