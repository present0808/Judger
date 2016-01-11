#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/time.h>

#define DEBUG 1

#define FORK_FAILED -1
#define WAIT4_FAILED -2

#define SUCCESS 0
#define CPU_TIME_LIMIT_EXCEEDED 1
#define REAL_TIME_LIMIT_EXCEEDED 2
#define MEMORY_LIMIT_EXCEEDED 3
#define RUNTIME_ERROR 4
#define SYSTEM_ERROR 5


struct result {
    int cpu_time;
    long memory;
    int real_time;
    int signal;
    int flag;
    int err;
};


struct config {
    int max_cpu_time;
    int max_memory;
    char path[200];
    char in_file[200];
    char out_file[200];
};


void set_timer(int sec, int ms, int is_cpu_time) {
    struct itimerval time_val;
    time_val.it_interval.tv_sec = time_val.it_interval.tv_usec = 0;
    time_val.it_value.tv_sec = sec;
    time_val.it_value.tv_usec = ms * 1000;
    if (setitimer(is_cpu_time ? ITIMER_VIRTUAL : ITIMER_REAL, &time_val, NULL) == -1) {
#ifdef DEBUG
        printf("settimer failed\n");
#endif
    }
}


void run(struct config *config, struct result *result) {
    int status;
    struct rusage resource_usage;
    struct timeval start, end;
    struct rlimit resource_limit;

    gettimeofday(&start, NULL);

    pid_t pid = fork();

    if (pid < 0) {
#ifdef DEBUG
        printf("fork failed\n");
#endif
        result->flag = SYSTEM_ERROR;
        result->err = FORK_FAILED;
        return;
    }

    if (pid > 0) {
        //parent process
#ifdef DEBUG
        printf("I'm parent process\n");
#endif
        if (wait4(pid, &status, 0, &resource_usage) == -1) {
#ifdef DEBUG
            printf("wait4 failed\n");
#endif
            result->flag = SYSTEM_ERROR;
            result->err = WAIT4_FAILED;
            return;
        }
        result->cpu_time = (int)(resource_usage.ru_utime.tv_sec * 1000 +
                           resource_usage.ru_utime.tv_usec / 1000 +
                           resource_usage.ru_stime.tv_sec * 1000 +
                           resource_usage.ru_stime.tv_usec / 1000);

        result->memory = resource_usage.ru_maxrss;
        result->flag = SUCCESS;

        if (WIFSIGNALED(status)) {
            int signal = WTERMSIG(status);
#ifdef DEBUG
            printf("signal %d\n", signal);
#endif
            result->signal = signal;
            if (signal == SIGALRM) {
                result->flag = REAL_TIME_LIMIT_EXCEEDED;
            }
            else if (signal == SIGVTALRM) {
                result->flag = CPU_TIME_LIMIT_EXCEEDED;
            }
            else if (signal == SIGSEGV) {
                if (result->memory > config->max_memory) {
                    result->flag = MEMORY_LIMIT_EXCEEDED;
                }
                else {
                    result->flag = RUNTIME_ERROR;
                }
            }
            else {
                result->flag = RUNTIME_ERROR;
            }
        }
        gettimeofday(&end, NULL);
        result->real_time = (int)(end.tv_sec * 1000 + end.tv_usec / 1000 - start.tv_sec * 1000 - start.tv_usec / 1000);
    }
    else {
        //child process
#ifdef DEBUG
        printf("I'm child process\n");
#endif
        resource_limit.rlim_cur = (int)(resource_limit.rlim_max = config->max_memory);
        if(setrlimit(RLIMIT_DATA, &resource_limit) != 0)
            printf("setrlimit failed");
        // cpu time
        set_timer(config->max_cpu_time / 1000, config->max_cpu_time % 1000, 1);
        // real time * 3
        set_timer(config->max_cpu_time / 1000 * 3, (config->max_cpu_time % 1000) * 3 % 1000, 0);

        //dup2(fileno(fopen(config->in_file, "r")), 0);
        //dup2(fileno(fopen(config->out_file, "w")), 1);

        execve(config->path, NULL, NULL);
#ifdef DEBUG
        printf("execve failed");
#endif
    }
}


int main() {
    struct config config;
    struct result result;

    config.max_cpu_time = 4300;
    config.max_memory = 300;

    strcpy(config.path, "/home/virusdefender/Desktop/judger/limit");
    strcpy(config.in_file, "/Users/virusdefender/Desktop/judger/in");
    strcpy(config.out_file, "/Users/virusdefender/Desktop/judger/out");

    run(&config, &result);

#ifdef DEBUG
    printf("cpu time %d\nreal time %d\nmemory %ld\nflag %d\nsignal %d", result.cpu_time, result.real_time, result.memory,
           result.flag, result.signal);
#endif

    return 0;
}