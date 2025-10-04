#include <stdio.h>
#include <unistd.h>
#include <pwd.h>

const char* module_name(void){ return "whoami"; }
void module_init(void){}
void module_run(int argc, char **argv){
    (void)argc; (void)argv;
    struct passwd *pw = getpwuid(geteuid());
    printf("Username : %s\n", pw ? pw->pw_name : "unknown");
}
void module_help(void){ printf("whoami - prints effective username\n"); }
