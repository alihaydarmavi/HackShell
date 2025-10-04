#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <errno.h>

#define MODULE_DIR "./modules"
#define MAX_MODULES 64
#define LINE_BUFSIZE 4096

/* Modül arayüzünü temsil eden struct */
typedef struct {
    char *name;            /* module_name() -> const char* */
    void (*init)(void);    /* module_init */
    void (*run)(int, char**); /* module_run */
    void (*help)(void);    /* module_help */
    void *dlhandle;        /* dlopen handle, so that we can dlclose */
} module_t;

static module_t modules[MAX_MODULES];
static int module_count = 0;

/* Yardımcı: string trim (baş/son boşlukları temizle) */
static char *trim(char *s){
    if(!s) return s;
    while(*s && (*s == ' ' || *s == '\t' || *s == '\n')) s++;
    if(*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while(end > s && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    *(end+1) = '\0';
    return s;
}

/* Basit tokenizer: satırı boşluklara göre argv biçimine ayırır.
 * Not: tırnak işleme vs. yoktur; gerektiğinde geliştirilmeli. */
static char **tokenize(char *line, int *out_argc){
    char **argv = calloc(128, sizeof(char*));
    int argc = 0;
    char *p = line;
    while(*p){
        while(*p == ' ' || *p == '\t') p++;
        if(!*p) break;
        char *start = p;
        while(*p && *p != ' ' && *p != '\t') p++;
        int len = p - start;
        char *tok = malloc(len+1);
        memcpy(tok, start, len);
        tok[len] = '\0';
        argv[argc++] = tok;
    }
    argv[argc] = NULL;
    *out_argc = argc;
    return argv;
}

/* Bellek temizleme: argv'yi free eder */
static void free_argv(char **argv, int argc){
    for(int i=0;i<argc;i++) free(argv[i]);
    free(argv);
}

/* Modules dizinini tara, .so dosyalarını yükle ve arayüze çek */
static void load_modules(const char *dirpath){
    DIR *d = opendir(dirpath);
    if(!d){
        fprintf(stderr, "[core] module dir '%s' acilamadi: %s\n", dirpath, strerror(errno));
        return;
    }
    struct dirent *entry;
    while((entry = readdir(d)) != NULL){
        /* Basit filtre: .so ile biten dosyalar */
        const char *name = entry->d_name;
        size_t L = strlen(name);
        if(L > 3 && strcmp(name + L - 3, ".so") == 0){
            if(module_count >= MAX_MODULES){
                fprintf(stderr, "[core] max module sayisi asildi\n");
                break;
            }
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", dirpath, name);
            void *h = dlopen(path, RTLD_NOW);
            if(!h){
                fprintf(stderr, "[core] dlopen failed for %s: %s\n", path, dlerror());
                continue;
            }
            /* Beklenen sembolleri ara */
            const char* (*module_name_fn)(void) = dlsym(h, "module_name");
            void (*module_init_fn)(void) = dlsym(h, "module_init");
            void (*module_run_fn)(int, char**) = dlsym(h, "module_run");
            void (*module_help_fn)(void) = dlsym(h, "module_help");

            if(!module_name_fn || !module_run_fn){
                fprintf(stderr, "[core] %s: gerekli semboller bulunamadi (module_name/module_run)\n", path);
                dlclose(h);
                continue;
            }

            const char *modname = module_name_fn();
            modules[module_count].name = strdup(modname);
            modules[module_count].init = module_init_fn; /* opsiyonel olabilir */
            modules[module_count].run  = module_run_fn;
            modules[module_count].help = module_help_fn; /* opsiyonel olabilir */
            modules[module_count].dlhandle = h;

            /* Opsiyonel: modül init() çağrısı */
            if(modules[module_count].init) modules[module_count].init();

            printf("[core] loaded module '%s' from %s\n", modules[module_count].name, path);
            module_count++;
        }
    }
    closedir(d);
}

/* Module arama: isim ile eşleşen modülü döndür */
static module_t *find_module(const char *name){
    for(int i=0;i<module_count;i++){
        if(strcmp(modules[i].name, name) == 0) return &modules[i];
    }
    return NULL;
}

/* Harici komut çalıştırma: fork + execvp */
static void run_external(char **argv){
    pid_t pid = fork();
    if(pid < 0){ perror("fork"); return; }
    if(pid == 0){
        /* Child */
        execvp(argv[0], argv);
        /* exec dönürse hata */
        fprintf(stderr, "[core] exec failed: %s\n", strerror(errno));
        _exit(127);
    } else {
        int status;
        waitpid(pid, &status, 0);
    }
}

/* Basit builtin handler: cd, exit, help (help basitçe gecistirilecek) */
static int handle_builtin(int argc, char **argv){
    if(argc == 0) return 0;
    if(strcmp(argv[0], "exit") == 0){
        /* Clean up modules before exit */
        for(int i=0;i<module_count;i++){
            if(modules[i].dlhandle) dlclose(modules[i].dlhandle);
            free(modules[i].name);
        }
        printf("bye\n");
        exit(0);
    }
    if(strcmp(argv[0], "cd") == 0){
        const char *dest = NULL;
        if(argc >= 2) dest = argv[1];
        if(!dest){
            struct passwd *pw = getpwuid(getuid());
            dest = pw ? pw->pw_dir : "/";
        }
        if(chdir(dest) < 0) perror("cd");
        return 1;
    }
    if(strcmp(argv[0], "help") == 0){
        /* Kullanıcının isteği: help komutu yazılmadı gibi davransın */
        printf("Help command not implemented yet.\n");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv){
    (void)argc; (void)argv;

    /* Modülleri yükle */
    load_modules(MODULE_DIR);

    char *line = NULL;
    size_t linecap = 0;

    while(1){
        /* Prompt: kullanıcı dizini göster */
        char cwd[PATH_MAX];
        if(getcwd(cwd, sizeof(cwd)) == NULL) strcpy(cwd, "?");
        printf("HackShell:%s$ ", cwd);
        fflush(stdout);

        ssize_t linelen = getline(&line, &linecap, stdin);
        if(linelen <= 0){ printf("\n"); break; }

        /* Trim ve boşsa devam et */
        if(line[linelen-1] == '\n') line[linelen-1] = '\0';
        char *trimmed = trim(line);
        if(!trimmed || trimmed[0] == '\0') continue;

        /* Tokenize */
        int targc = 0;
        char **targv = tokenize(trimmed, &targc);
        if(targc == 0){ free_argv(targv, targc); continue; }

        /* Builtin kontrolü */
        if(handle_builtin(targc, targv)){
            free_argv(targv, targc);
            continue;
        }

        /* Eğer modül varsa, çağır */
        module_t *m = find_module(targv[0]);
        if(m){
            /* module_run(argc, argv) */
            m->run(targc, targv);
            free_argv(targv, targc);
            continue;
        }

        /* Aksi halde harici komut çalıştır */
        run_external(targv);
        free_argv(targv, targc);
    }

    free(line);
    /* cleanup */
    for(int i=0;i<module_count;i++){
        if(modules[i].dlhandle) dlclose(modules[i].dlhandle);
        free(modules[i].name);
    }
    return 0;
}
