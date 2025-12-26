#define _GNU_SOURCE

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <libgen.h>
#include <ctype.h>

#define CPU_INDEX_USER_BASE     1
#define CPU_INDEX_INTERNAL_BASE 0

#define USER_TO_INTERNAL(cpu)   ((cpu) - CPU_INDEX_USER_BASE + CPU_INDEX_INTERNAL_BASE)
#define INTERNAL_TO_USER(cpu)   ((cpu) - CPU_INDEX_INTERNAL_BASE + CPU_INDEX_USER_BASE)

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

typedef enum {
    ERR_NONE = 0,
    ERR_INVALID_PID,
    ERR_INVALID_CPU,
    ERR_NO_CPU_ASSIGNED,
    ERR_SET_AFFINITY,
    ERR_GET_AFFINITY,
    ERR_PERMISSION
} error_code_t;

static void print_usage(const char *prog_name)
{
    fprintf(stdout,
        "Usage: %s [PID] [CPU_ID ...]\n"
        "\n"
        "  PID       Target process ID (default: self)\n"
        "  CPU_ID    CPU numbers to assign (starting from 1)\n"
        "\n"
        "Examples:\n"
        "  %s              Show current process affinity\n"
        "  %s 1234         Show PID 1234 affinity\n"
        "  %s 1234 1 3     Assign PID 1234 to CPU 1, 3\n"
        "  %s 0 1 2        Assign self to CPU 1, 2\n"
        "\n",
        prog_name, prog_name, prog_name, prog_name, prog_name
    );
}

static int is_valid_number(const char *str)
{
    if (str == NULL || *str == '\0') {
        return 0;
    }
    
    if (*str == '-') {
        str++;
    }
    
    while (*str != '\0') {
        if (!isdigit((unsigned char)*str)) {
            return 0;
        }
        str++;
    }
    
    return 1;
}

static int get_online_cpu_count(void)
{
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return (count > 0) ? (int)count : -1;
}

static error_code_t set_cpu_affinity(pid_t pid, int argc, char **argv, int start_index)
{
    cpu_set_t cpu_set;
    int set_count = 0;
    int online_cpus = get_online_cpu_count();
    
    CPU_ZERO(&cpu_set);
    
    for (int i = start_index; i < argc; i++) {
        if (!is_valid_number(argv[i])) {
            fprintf(stderr, "warning: invalid argument ignored (argv[%d]=\"%s\")\n", i, argv[i]);
            continue;
        }
        
        int cpu_user = atoi(argv[i]);
        
        if (cpu_user < CPU_INDEX_USER_BASE) {
            fprintf(stderr, "warning: cpu number must be >= %d (got: %d)\n",
                    CPU_INDEX_USER_BASE, cpu_user);
            continue;
        }
        
        int cpu_internal = USER_TO_INTERNAL(cpu_user);
        
        if (online_cpus > 0 && cpu_internal >= online_cpus) {
            fprintf(stderr, "warning: cpu %d does not exist (online: 1-%d)\n",
                    cpu_user, online_cpus);
            continue;
        }
        
        if (cpu_internal >= (int)CPU_SETSIZE) {
            fprintf(stderr, "warning: cpu %d exceeds max supported (%d)\n",
                    cpu_user, (int)CPU_SETSIZE);
            continue;
        }
        
        CPU_SET(cpu_internal, &cpu_set);
        set_count++;
    }
    
    if (set_count == 0) {
        return ERR_NO_CPU_ASSIGNED;
    }
    
    if (sched_setaffinity(pid, sizeof(cpu_set), &cpu_set) == -1) {
        if (errno == EPERM) {
            return ERR_PERMISSION;
        }
        return ERR_SET_AFFINITY;
    }
    
    fprintf(stdout, "affinity set: %d cpu(s)\n", set_count);
    return ERR_NONE;
}

static error_code_t show_cpu_affinity(pid_t pid)
{
    cpu_set_t cpu_set;
    int current_cpu = -1;
    int online_cpus = get_online_cpu_count();
    
    CPU_ZERO(&cpu_set);
    
    if (sched_getaffinity(pid, sizeof(cpu_set), &cpu_set) == -1) {
        return ERR_GET_AFFINITY;
    }
    
#if defined(__GLIBC__) && __GLIBC__ >= 2
    if (pid == 0 || pid == getpid()) {
        current_cpu = sched_getcpu();
    }
#endif
    
    int cpu_count = CPU_COUNT(&cpu_set);
    fprintf(stdout, "pid: %ld, cpus: %d\n", (long)pid, cpu_count);
    
    fprintf(stdout, "allowed: ");
    int first = 1;
    int limit = (online_cpus > 0) ? online_cpus : (int)CPU_SETSIZE;
    
    for (int i = 0; i < limit; i++) {
        if (CPU_ISSET(i, &cpu_set)) {
            if (!first) {
                fprintf(stdout, ",");
            }
            fprintf(stdout, "%d", INTERNAL_TO_USER(i));
            if (i == current_cpu) {
                fprintf(stdout, "*");
            }
            first = 0;
        }
    }
    fprintf(stdout, "\n");
    
    if (current_cpu >= 0) {
        fprintf(stdout, "(* = currently running)\n");
    }
    
    return ERR_NONE;
}

int main(int argc, char **argv)
{
    pid_t target_pid = getpid();
    error_code_t err;
    
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage(basename(argv[0]));
        return EXIT_SUCCESS;
    }
    
    if (argc >= 2) {
        if (!is_valid_number(argv[1])) {
            fprintf(stderr, "error: invalid pid \"%s\"\n", argv[1]);
            return EXIT_FAILURE;
        }
        
        long pid_val = atol(argv[1]);
        if (pid_val < 0) {
            fprintf(stderr, "error: pid must be >= 0\n");
            return EXIT_FAILURE;
        }
        
        target_pid = (pid_val == 0) ? getpid() : (pid_t)pid_val;
    }
    
    if (argc >= 3) {
        err = set_cpu_affinity(target_pid, argc, argv, 2);
        
        switch (err) {
            case ERR_NONE:
                break;
            case ERR_NO_CPU_ASSIGNED:
                fprintf(stderr, "error: no valid cpu specified\n");
                return EXIT_FAILURE;
            case ERR_PERMISSION:
                fprintf(stderr, "error: permission denied\n");
                return EXIT_FAILURE;
            case ERR_SET_AFFINITY:
                perror("sched_setaffinity");
                return EXIT_FAILURE;
            default:
                break;
        }
    }
    
    err = show_cpu_affinity(target_pid);
    
    if (err == ERR_GET_AFFINITY) {
        if (errno == ESRCH) {
            fprintf(stderr, "error: process %ld not found\n", (long)target_pid);
        }
        else {
            perror("sched_getaffinity");
        }
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
