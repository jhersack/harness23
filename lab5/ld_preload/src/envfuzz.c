// $CC envfuzz.c -o envfuzz.so -shared -fPIC -ldl -g

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <poll.h>

#define BLOCK_SIZE 64
#define EXPANSION_FACTOR 256
#define FUZZ_TAG "fuzzme"

extern void *malloc(size_t size);
extern void *calloc(size_t count, size_t size);
extern void qsort(void *base, size_t nel, size_t width, int (*compar)(const void *, const void *));

static int (*main_orig)(int, char **, char **);
static char *(*getenv_orig)(const char *);
static int (*read_orig)(int, void *, size_t);
static int (*system_orig)(const char *);
static FILE *(*popen_orig)(const char *, const char *);


char **fuzz_envp = NULL;
int fuzz_fd = -1;


// LD_PRELOAD'd getenv function (checks for fuzzed envvars first)
char *getenv(const char *name) {
/*return fuzzed_envp[key]*/
}


// LD_PRELOAD'd read function (replaces stdin with fuzzed fd)
ssize_t read(int fd, void *buf, size_t sz) {
    if (fd == 0) fd = fuzz_fd;
    return read_orig(fd, buf, sz);
}


// gets length of envvar name
int name_len(char *env) {
    return strchr(env, '=') - env;
}


// compares two strings in qsort compatible way
int cmp(const void *a, const void *b) {
    const char **ia = (const char **) a;
    const char **ib = (const char **) b;
    return strcmp(*ia, *ib);
}

void clean_fs() {
    remove("/getfuzzed");
}

void check_injection() {
/*   if file_exists("/getfuzzed"):
       print("injection from {}".format(cmd))
       abort()
       */
}


int system(const char *cmd) {
/* 
clean_fs()
   ret = system_orig(cmd)
   check_injection(cmd)
   return ret
   */
}


FILE *popen(const char *cmd, const char *mode) {
/*   clean_fs()
   ret = popen_orig(cmd, rw)
   check_injection(cmd)
   return ret
   */
}


// reads in envp for fuzzed envvars and loads with fuzzed data from fuzz_fd
int load_fuzz_envp(char **envp) {
    char **tracer, **fuzz_tracer;
    char *var, *buf;
    int count, size, i, envp_len;

    envp_len = 0;
    count = 0;
    size = 0;
    for (tracer = envp; *tracer != NULL; tracer++) {
        envp_len++;
        var = strchr(*tracer, '=') + 1;
        if (strcmp(var, FUZZ_TAG) == 0) {
            count++;
            size += name_len(*tracer) + 1 + BLOCK_SIZE * EXPANSION_FACTOR + 1; // name=fuzz\0
        }
    }

    // ensure that envp is arranged the same everytime
    qsort(envp, envp_len, sizeof(*envp), cmp);

    fuzz_envp = calloc(count + 1, sizeof(*fuzz_envp));
    if (fuzz_envp == NULL) return -1;

    buf = calloc(size, 1);
    if (size != 0 && buf == NULL) return -1;

    fuzz_tracer = fuzz_envp;
    for (tracer = envp; *tracer != NULL; tracer++) {
        var = strchr(*tracer, '=') + 1;
        if (strcmp(var, FUZZ_TAG) == 0) {
            *fuzz_tracer = buf;
            strncpy(buf, *tracer, name_len(*tracer));
            strcat(buf, "=");
            read(fuzz_fd, &buf[strlen(buf)], BLOCK_SIZE);
            
            fuzz_tracer++;
            buf += name_len(*tracer) + 1 + BLOCK_SIZE * EXPANSION_FACTOR + 1;
        }
    }
}


// Our fake main() that gets called by __libc_start_main()
int main_hook(int argc, char **argv, char **envp)
{
    int ret;
    char **fuzz_envp;

    if (argc < 2) {
        printf("must provide fuzzed file as last argument!\n");
        return 1;
    }

    fuzz_fd = open(argv[argc - 1], O_RDONLY);
    if (fuzz_fd < 0) {
        printf("failed to open fuzz file\n");
        return 1;
    }

    if (load_fuzz_envp(envp) < 0) {
        printf("failed to load fuzz envp!\n");
        return 1;
    }

    clean_fs();

    argc -= 1;
    argv[argc] = NULL;

    // pass in 0xdeadbeaf to ensure program is not touching envp directly
    ret = main_orig(argc, argv, (char **) 0xdeadbeaf);

    return ret;
}


int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc,
    char **argv,
    int (*init)(int, char **, char **),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end)
{

/*
   fuzzed = open(argv[-1])
   for env in envp:
       if env.data == "fuzzme":
           env.data = fuzzed.read(ENV_SIZE)
   fuzzed_envp = envp
   return main(argc, argv, envp)*/

}
