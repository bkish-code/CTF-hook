/*
 * This program has vulnerabilities to be exploited.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>

void sig_handler(int signum) {
    (void)signum;
    printf("Timeout\n");
    exit(0);
}

void init() {
    alarm(60);                  
    signal(SIGALRM, sig_handler);

    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    chdir(getenv("HOME"));        
}
 
// Spawns a shell using the execveat syscall.
void execveat_sim(void *arg) {
    printf("[system] execveat_sim invoked with arg=%p\n", arg);
    printf("[+] Launching developer console via execveat syscall...\n\n");

    char *const argv[] = {"/bin/sh", NULL};
    char *const envp[] = {NULL};

    /* execveat(AT_FDCWD, "/bin/sh", argv, envp, 0) */
    syscall(322, (long)-100, "/bin/sh", argv, envp, 0);

    perror("execveat failed");
    exit(1);
}
 
// Note structure
// Important: the cleanup_callback is stored right after the data pointer/size
// so a heap overflow in edit_note() can reach and overwrite it.
struct Note {
    char *data;                    
    size_t size;                  
    void (*cleanup_callback)(void *);  // hint: function pointer we can hijack
};
 
// Creates a new note. We allocate the data buffer first, 
// then the Note struct. This layout makes the heap overflow.
struct Note *create_note() {
    char *buf = malloc(64);
    if (!buf) return NULL;

    struct Note *n = malloc(sizeof(struct Note));
    if (!n) {
        free(buf);
        return NULL;
    }

    n->data = buf;
    n->size = 64;
    n->cleanup_callback = NULL;

    printf("Created note (data @ %p)\n", (void *)n->data);
    return n;
}

/* 
 * Edit a note - hint: a vulnerability exists here.
 * fgets is told it can read 40 bytes more than the actual buffer size.
 * This allows a heap overflow that can reach the cleanup_callback pointer.
 */
void edit_note(struct Note *n) {
    printf("Edit note (%zu bytes max): ", n->size);
    fgets(n->data, (int)(n->size) + 40, stdin);   // hint: overflow here
}

// View logs -> another vulnerability here: format string bug.
// Hint: use this to leak addresses (PIE base) before doing the heap exploit.
void view_logs() {
    char buf[128];

    printf("Enter log filter: ");
    fgets(buf, sizeof(buf), stdin);

    printf(buf); // Look: format string vulnerability
}
 
// Delete a note.
// If the cleanup_callback has been overwritten, it will call our designated address.
void delete_note(struct Note **np) {
    struct Note *n = *np;

    if (n->cleanup_callback) {
        printf("Running cleanup callback.\n");
        n->cleanup_callback(n->data);  // call the hijack function pointer
    } else {
        printf("Deleting note.\n");
        free(n->data);
        free(n);
    }

    *np = NULL;
}

// menu
void menu() {
    puts("\n+-+-+- Notes Menu -+-+-+");
    puts("1. Create a note");
    puts("2. Edit note");
    puts("3. Delete note");
    puts("4. View logs");
    puts("5. Quit");
    printf("> ");
}

// main 
int main() {
    struct Note *note = NULL;

    init();

    while (1) {
        menu();

        int choice;
        if (scanf("%d%*c", &choice) != 1) {
            puts("Invalid input.");
            return 0;
        }

        if (choice == 1) {
            if (note) {
                puts("A note already exists. Delete it first.");
                continue;
            }
            note = create_note();
            if (!note)
                puts("Allocation failed.");
        }
        else if (choice == 2) {
            if (!note) {
                puts("No note created.");
                continue;
            }
            edit_note(note);
        }
        else if (choice == 3) {
            if (!note) {
                puts("No note created.");
                continue;
            }
            delete_note(&note);
        }
        else if (choice == 4) {
            view_logs();
        }
        else if (choice == 5) {
            break;
        }
        else {
            puts("Choice should be 1-5.");
        }
    }

    return 0;
}
