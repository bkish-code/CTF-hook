CTF-pwn-tips
===========================


# Catalog
* [Overflow](#overflow)
* [Find string in gdb](#find-string-in-gdb)
* [Binary Service](#binary-service)
* [Find specific function offset in libc](#find-specific-function-offset-in-libc)
* [Find '/bin/sh' or 'sh' in library](#find-binsh-or-sh-in-library)
* [Leak stack address](#leak-stack-address)
* [Fork problem in gdb](#fork-problem-in-gdb)
* [Secret of a mysterious section - .tls](#secret-of-a-mysterious-section---tls)
* [Predictable RNG(Random Number Generator)](#predictable-rngrandom-number-generator)
* [Make stack executable](#make-stack-executable)
* [Use one-gadget-RCE instead of system](#use-one-gadget-rce-instead-of-system)
* [Hijack hook function](#hijack-hook-function)
* [Use printf to trigger malloc and free](#use-printf-to-trigger-malloc-and-free)
* [Use execveat to open a shell](#use-execveat-to-open-a-shell)


## Overflow

In the demonstrations, use the following:
* `char buf[40]` - has 39 bytes for characters and 1 byte for \0 null terminator.
* `signed int num` - holds 4 byte integer, negative or positive.

Note the following unsafe input functions:

### scanf

   a. **scanf("%s", buf)**
       * **%s** doesn't have bounds check which can lead to an overflow.
       * **pwnable** if we enter over 39 characters.

   b. `scanf("%39s", buf)`
   
       * `%39s` reads only 39 bytes from the user input and puts NULL byte at the end of input.
       * *not pwnable* becuase buf can hold up to 40 bytes. 

   c. `scanf("%40s", buf)`
   
       * It reads **40 bytes** from user input, but it also **adds a NULL byte at the end of input** for a total of 41 bytes.
       * Therefore, it has **off-by-one-byte-overflow** since buf[40] = '\0' <-- writes past buf (stack overflow). 
       * **pwnable** as '\0' overwrites whatever follows the buf array.

   d. `scanf("%d", &num)`
   
       * This allows the user to enter a negative or positive integer. 
	   * This function is used with `alloca(num)`
           * alloca() is designed for positive numbers only. It makes the stack grow downward, or from higher to lower memory addresses.
		   	   * It uses `sub esp, eax  ; eax = n`
		   * alloca(negative_number) makes the stack grow upward, towards higher memory addresses, in the wrong direction.
		   * alloca does not check if numbers are > 0; *num* should be an *unsigned integer*. 
        * If num is negative, it will overwrite the stack frame.
           * E.g. [Seccon CTF quals 2016 cheer_msg](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/cheer-msg-100)

### gets

a. `gets(buf)`

    * No boundary check. It continues to read user input until it sees '\n'.
    * Like scanf, it read user input but stops until it sees '\n'.
    * **pwnable** as it continues to read user input - past whatever buf can store.

b. `fgets(buf, 40, stdin)`

    * It takes only **39 bytes** from the user input and puts NULL byte at the end of input.
    * **useless** since buf can hold 40 bytes.

### read

* `read(stdin, buf, 40)`
    * It copies **40 bytes** from the user input into buf. That's it.
    * It does **not** put a NULL byte at the end of input.
    * It does **not** stop for '\n'.
    * It does **not** check for overflow.
    * It seems safe, but it may have **information leak**.
    * **leakable** if `printf("%s\n,buf);` and there is no '\n'.
       * printf continues to print until it encounters a '\n'.
       * It can read stack content, registers, canary, return address, etc.

E.g.

**memory layout**
```
0x7fffffffdd00: 0x4141414141414141      0x4141414141414141
0x7fffffffdd10: 0x4141414141414141      0x4141414141414141
0x7fffffffdd20: 0x4141414141414141      0x00007fffffffe1cd
```

* If there is a `printf` or `puts` used to output the buf, it will keep outputting until reaching NULL byte.
* In this case, we can get `'A'*40 + '\xcd\xe1\xff\xff\xff\x7f'`.

* `fread(buf, 1, 40, stdin)`
    * The same as `read` but reads raw bytes from a `FILE*` stream.
    * **leakable** as it does not add null terminator, stop at newline, and does not check for overflow.

### strcpy

Let's use a second buffer: `char buf2[60]`

* `strcpy(buf, buf2)`
    * The function does not have boundary checks.
    * So, it copies the content of buf2, 60 bytes or until it reaches a NULL byte. But buf is only 40 bytes long.
    * All of buf2 is copied into buf, including NULL byte which gets added at the end, past buf. 
    * Therefore, it could overflow by up to 20 bytes.
    * **pwnable** as overflow begins at buf[40] = buf2[40]. Overflow ends at buf[40+] or buf[60] = '\0'.

* `strncpy(buf, buf2, 40)` && `memcpy(buf, buf2, 40)`
    * It copies 40 bytes from buf2 to buf, but it does **not** put a NULL byte at the end.
    * Without a NULL byte at the end, there could be an **information leak**.
    * **leakable** if `printf("%s\n", buf);` is used and NULL bytes was not added.
       * printf continues to print until it encounters a NULL byte.

### strcat

Let's continue to use `char buf[40]` and a second buffer: `char buf2[60]`

* `strcat(buf, buf2)`
    * Of course, it may cause **overflow** if `length(buf)` isn't large enough.
    * It puts NULL byte at the end, it may cause **one-byte-overflow**.
    * In some cases, we can use this NULL byte to change stack address or heap address.
    * **pwnable**

* `strncat(buf, buf2, n)`
    * Almost the same as `strcat`, but with size limitation.
    * **pwnable**
    * E.g. [Seccon CTF quals 2016 jmper](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/jmper-300)


## Find string in gdb

In the problem of [SSP](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf), we need to find out the offset between `argv[0]` and the input buffer.
So, we find the environ first because evnviron is a exposed pointer and you can use it to computer where *argv[0]* is. `argv` is not a global symbol and gdb cannot print *argv* unless you are inside main. Subtracting 0x10 from `environ` gives *argv[0]*. We want *argv[0]* because it gives us a stable, predictable anchor on the stack. In SSP problems, that anchor is essential for calculating the offset between your input buffer and other stack objects. *argv[0]* is always in the same relative position, always a valid pointer to a string, always readable, and always placed before envp. It is a good way to find where the canary is located.

### gdb

* Use `p/x ((char **)environ)` in gdb, and the address of argv[0] will be the `output - 0x10`

E.g.

```
(gdb) p/x (char **)environ
$9 = 0x7fffffffde38
(gdb) x/gx 0x7fffffffde38-0x10
0x7fffffffde28: 0x00007fffffffe1cd
(gdb) x/s 0x00007fffffffe1cd
0x7fffffffe1cd: "/home/naetw/CTF/seccon2016/check/checker"
```

### [gdb peda](https://github.com/longld/peda)

* Use `searchmem "/home/naetw/CTF/seccon2016/check/checker"`
* Then use `searchmem $result_address`

```
gdb-peda$ searchmem "/home/naetw/CTF/seccon2016/check/checker"
Searching for '/home/naetw/CTF/seccon2016/check/checker' in: None ranges
Found 3 results, display max 3 items:
[stack] : 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffed7c ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffefcf ("/home/naetw/CTF/seccon2016/check/checker")
gdb-peda$ searchmem 0x7fffffffe1cd
Searching for '0x7fffffffe1cd' in: None ranges
Found 2 results, display max 2 items:
   libc : 0x7ffff7dd33b8 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffde28 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
```

## Binary Service

Normal:

* `ncat -vc ./binary -kl 127.0.0.1 $port`

With specific library in two ways:

* `ncat -vc 'LD_PRELOAD=/path/to/libc.so ./binary' -kl 127.0.0.1 $port`
* `ncat -vc 'LD_LIBRARY_PATH=/path/of/libc.so ./binary' -kl 127.0.0.1 $port`

After this, you can connect to binary service by command `nc localhost $port`.

## Find specific function offset in libc

If we leaked libc address of certain function successfully, we could use get libc base address by subtracting the offset of that function.

### Manually

* `readelf -s $libc | grep ${function}@`

E.g.

```
$ readelf -s libc-2.19.so | grep system@
    620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
   1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
```

### Automatically

* Use [pwntools](https://github.com/Gallopsled/pwntools), then you can use it in your exploit script.

E.g.

```python
from pwn import *

libc = ELF('libc.so')
system_off = libc.symbols['system']
```

## Find '/bin/sh' or 'sh' in library

Need libc base address first

### Manually

* `objdump -s libc.so | less` then search 'sh'
* `strings -tx libc.so | grep /bin/sh`

### Automatically

* Use [pwntools](https://github.com/Gallopsled/pwntools)

E.g.

```python
from pwn import *

libc = ELF('libc.so')
...
sh = base + next(libc.search('sh\x00'))
binsh = base + next(libc.search('/bin/sh\x00'))
```

## Leak stack address

**constraints**:

* Have already leaked libc base address
* Can leak the content of arbitrary address

There is a symbol `environ` in libc, whose value is the same as the third argument of `main` function, `char **envp`.
The value of `char **envp` is on the stack, thus we can leak stack address with this symbol.

```
(gdb) list 1
1       #include <stdlib.h>
2       #include <stdio.h>
3
4       extern char **environ;
5
6       int main(int argc, char **argv, char **envp)
7       {
8           return 0;
9       }
(gdb) x/gx 0x7ffff7a0e000 + 0x3c5f38
0x7ffff7dd3f38 <environ>:       0x00007fffffffe230
(gdb) p/x (char **)envp
$12 = 0x7fffffffe230
```

* `0x7ffff7a0e000` is current libc base address
* `0x3c5f38` is offset of `environ` in libc

This [manual](https://www.gnu.org/software/libc/manual/html_node/Program-Arguments.html) explains details about `environ`.

## Fork problem in gdb

When you use **gdb** to debug a binary with `fork()` function, you can use the following command to determine which process to follow (The default setting of original gdb is parent, while that of gdb-peda is child.):

* `set follow-fork-mode parent`
* `set follow-fork-mode child`

Alternatively, using `set detach-on-fork off`, we can then control both sides of each fork. Using `inferior X` where `X` is any of the numbers that show up for `info inferiors` will switch to that side of the fork. This is useful if both sides of the fork are necessary to attack a challenge, and the simple `follow` ones above aren't sufficient.

## Secret of a mysterious section - .tls

If you force malloc to use mmap (by requesting a large enough allocation), the returned memory region is placed right before the Thread‑Local Storage (.tls) segment.

And `.tls` contains high‑value secrets: the canary, main_arena, and a stable stack pointer.

This lets you leak those secrets if you have an arbitrary‑read primitive.

**Requirements for .tls leak trick**:

1. We need the `malloc` function so we can malloc with arbitrary size <brk>
   If we request a chunk large enough (by using `malloc(0x21000)` ), glibc uses the mmap path. This large malloc gives us a chunk that is placed below `.tls` in virtual memmory. We then can read above mmap'd chunk to reach `.tls`. 
2. Arbitrary address leaking <brk>
   Once the chunk below .tls, we need to read memory at arbitrary addresses. .tls contains: <brk>
   1. the **stack canary** (value of __stack_chk_guard)
   2. the **pointer to** `main_arena` (leaks libc base)
   3. a **stable stack pointer snapshot** (helps defeat PIE)
   4. other thread local values
   5. If we have arbitrary read, we can do <brk>
   `read( tls_addr + offset )` and extract all of the above secrets. 
   

We want to read upward, from mmap into `.tls`.
We make `malloc` use `mmap` to allocate memory(size 0x21000 is enough). In general, these pages will be placed at the address just before `.tls` section.

### The attack flow

1. Use malloc(0x21000) <brk>
   → glibc returns an mmap chunk placed just below .tls.
2. Use your arbitrary leak <brk> 
   → read memory above the chunk
   → reach .tls
3. Extract secrets
   * canary → bypass SSP
   * main_arena pointer → compute libc base
   * stack pointer snapshot → compute stack offsets


**Before calling mmap:**

```
7fecbfe4d000-7fecbfe51000 r--p 001bd000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe51000-7fecbfe53000 rw-p 001c1000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe53000-7fecbfe57000 rw-p 00000000 00:00 0
7fecbfe57000-7fecbfe7c000 r-xp 00000000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc0068000-7fecc006a000 rw-p 00000000 00:00 0              <- .tls section
7fecc0078000-7fecc007b000 rw-p 00000000 00:00 0
7fecc007b000-7fecc007c000 r--p 00024000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc007c000-7fecc007d000 rw-p 00025000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
```

**After call mmap:**

```
7fecbfe4d000-7fecbfe51000 r--p 001bd000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe51000-7fecbfe53000 rw-p 001c1000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe53000-7fecbfe57000 rw-p 00000000 00:00 0
7fecbfe57000-7fecbfe7c000 r-xp 00000000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc0045000-7fecc006a000 rw-p 00000000 00:00 0              <- memory of mmap + .tls section
7fecc0078000-7fecc007b000 rw-p 00000000 00:00 0
7fecc007b000-7fecc007c000 r--p 00024000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc007c000-7fecc007d000 rw-p 00025000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
```

## Predictable RNG(Random Number Generator)

When the binary uses the RNG to make the address of important information or sth, we can guess the same value if it's predictable.

Assuming that it's predictable, we can use [ctypes](https://docs.python.org/2/library/ctypes.html) which is a build-in module in Python.

**ctypes** allows calling a function in DLL(Dynamic-Link Library) or Shared Library.

Therefore, if binary has an init_proc like this:

```c
srand(time(NULL));
while(addr <= 0x10000){
    addr = rand() & 0xfffff000;
}
secret = mmap(addr,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,-1,0);
if(secret == -1){
    puts("mmap error");
    exit(0);
}
```

Then we can use **ctypes** to get the same value of addr.

```python
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/path/to/dll')
LIBC.srand(LIBC.time(0))
addr = LIBC.rand() & 0xfffff000
```

## Make stack executable

* [link1](http://radare.today/posts/defeating-baby_rop-with-radare2/)
* [link2](https://sploitfun.wordpress.com/author/sploitfun/)
* Haven't read yet orz

## Use one-gadget-RCE instead of system

To get a shell, we need to call `system('/bin/sh')`. This requires us to manipulate parameters and hijack a function to `system`. However, we cannot always manipulate the parameters.  

Instead, we can use a one‑gadget RCE instead of calling system("/bin/sh"). This technique avoids the need of the /bin/sh string. 

**Requirements**:

1. You must know the libc base address <br>
   One‑gadgets live inside libc, so their absolute address is:

   ```one_gadget_addr = libc_base + offset_of_one_gadget```
   
   If you don’t know the libc base, you cannot compute the real address of the gadget.

2. You must be able to write to an arbitrary address.
   To trigger the one‑gadget, you overwrite a function pointer inside libc, usually:
   * __free_hook
   * __malloc_hook (older glibc)
   * sometimes vtable pointers or other hooks

   Example:
   
   ```
   __free_hook = one_gadget_addr
   ```
   
   Then when the program calls:

   ```
   free(ptr);
   ```

   glibc internally does:

   ```
   if (__free_hook)
    __free_hook(ptr);
   ```

   So execution jumps directly into your one‑gadget.

   This gives you a shell without needing:
   * a pop rdi; ret gadget
   * a /bin/sh string
   * a full ROP chain

Use [one-gadget-RCE](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf)!

With **one-gadget-RCE**, we can just hijack `.got.plt` or something that controls eip to make program jump to **one-gadget**.

A one‑gadget is a location inside libc where the instructions already perform:

```execve("/bin/sh", rdi, rsi)```

or a variant of it.

These gadgets are placed inside libc and can be found with tools like one_gadget. They work only if certain registers satisfy constraints (e.g., rsi == NULL, rdx == NULL, etc.). When triggered inside glibc internals (like during free()), those constraints are naturally satisfied.

There are lots of **one-gadgets** in libc. Each one has different constraints. Each constraint is about the state of registers.

For example,

* ebx is the address of `rw-p` area of libc
* [esp+0x34] == NULL

**Tool to get contraints:**  [one_gadget](https://github.com/david942j/one_gadget) 


If we can satisfy those constraints, we can get a shell.

## Hijack hook function

Inside glibc, or malloc.h, global variables exist, such as:
* _ _malloc_hook
* _ _free_hook
* _ _realloc_hook
>[!NOTE] glibc 2.34+ removed these hooks.

These are **function pointers** used for debugging memory allocators. They are  *NULL* by default. Because they are global variables in writable memory, an attacker can write an address to them.

```
// Normal glibc behavior:
free(ptr);  // Calls _ _libc_free() internally

// After attacker overwrites _ _free_hook:
_ _free_hook = 0xdeadbeef;  // Attacker's address

// Now when victim calls:
free(ptr);  
// glibc executes: _ _free_hook(ptr, ...) 
// Jumps to 0xdeadbeef (attacker's code/gadget)
```

### Hijacking Explained

When `free()` is called, glibc does this:
```
if (_ _free_hook !NULL)
    (*_ _free_hook)(ptr, return_address);
```

If you overwrite `_ _free_hook` with the address of a gadget, then the next time the program calls `free()`, glibc jumps to your payload.

### Requirements for the attack

1. You must know the **libc base address** to compute the absolute address of `_ _free_hook` or `_ _malloc_hook`.
2. You must have arbitrary write - be able to write a value of a memory address or a write-what-primitive.
   ```
   // Vulnerability: arbitrary write primitive
   *attacker_controlled_address = attacker_controlled_value;
   
   // Real-world example: buffer overflow with index control
   int buffer[10];
   buffer[user_index] = user_value;  // No bounds checking
   ```

3. The program uses `malloc`, `free`, or `realloc`.

#### Example of Vulnerability
```
// The "write-what-where" vulnerability from use-after-free
struct node {
    void (*callback)(int);
    int data;
};

struct node* ptr = malloc(sizeof(struct node));
free(ptr);
// Attacker reuses the freed memory
struct attacker_control* evil = malloc(sizeof(struct attacker_control));
evil->target_address = &__free_hook;  // Where
evil->target_value = shellcode_address;  // What

// When the original code uses the freed pointer:
ptr->callback(ptr->data);  // Write-what-where primitive triggers
```

### Exploitation Steps
1. Leak a libc address.
2. Compute libc base.
3. Compute the address of `_ _free_hook`:<br>
   `free_hook = libc_base + offset(_ _free_hook)`
4. Compute the address of one-gadget:<br>
   `one_gadget = libc_base + offset(one_gadget)`.
5. Use the arbitrary write to overwrite:<br>
   `*(void **)free_hook = one_gadget`.
6. Trigger the `free()` call in the program.
7. Get the Shell.

By manual:

> The GNU C Library lets you modify the behavior of `malloc`, `realloc`, and `free` by specifying appropriate hook functions. You can use these hooks to help you debug programs that use dynamic memory allocation, for example.


Since they are used to help us debug programs, they are writable during the execution.

```
0xf77228e0 <__free_hook>:       0x00000000
0xf7722000 0xf7727000 rw-p      mapped
```

Let's look into the [src](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#2917) of malloc.c. I will use `__libc_free` to demo.

```c
void (*hook) (void *, const void *) = atomic_forced_read (__free_hook);
if (__builtin_expect (hook != NULL, 0))
{
    (*hook)(mem, RETURN_ADDRESS (0));
    return;
}
```

It checks the value of `__free_hook`. If it's not NULL, it will call the hook function first. Here, we would like to use **one-gadget-RCE**. Since hook function is called in the libc, the constraints of **one-gadget** are usually satisfied.

## Use printf to trigger malloc and free

Look into the source of printf, there are several places which may trigger malloc. Take [vfprintf.c line 1470](https://code.woboq.org/userspace/glibc/stdio-common/vfprintf.c.html#1470) for example:

```c
#define EXTSIZ 32
enum { WORK_BUFFER_SIZE = 1000 };

if (width >= WORK_BUFFER_SIZE - EXTSIZ)
{
    /* We have to use a special buffer.  */
    size_t needed = ((size_t) width + EXTSIZ) * sizeof (CHAR_T);
    if (__libc_use_alloca (needed))
        workend = (CHAR_T *) alloca (needed) + width + EXTSIZ;
    else
    {
        workstart = (CHAR_T *) malloc (needed);
        if (workstart == NULL)
        {
            done = -1;
            goto all_done;
        }
        workend = workstart + width + EXTSIZ;
    }
}
```

We can find that `malloc` will be triggered if the width field is large enough.(Of course, `free` will also be triggered at the end of printf if `malloc` has been triggered.) However, WORK_BUFFER_SIZE is not large enough, since we need to go to **else** block. Let's take a look at `__libc_use_alloca` and see what exactly the minimum size of width we should give.

```c

/* Minimum size for a thread.  We are free to choose a reasonable value.  */
#define PTHREAD_STACK_MIN        16384

#define __MAX_ALLOCA_CUTOFF        65536

int __libc_use_alloca (size_t size)
{
    return (__builtin_expect (size <= PTHREAD_STACK_MIN / 4, 1)
        || __builtin_expect (__libc_alloca_cutoff (size), 1));
}

int __libc_alloca_cutoff (size_t size)
{
	return size <= (MIN (__MAX_ALLOCA_CUTOFF,
					THREAD_GETMEM (THREAD_SELF, stackblock_size) / 4
					/* The main thread, before the thread library is
						initialized, has zero in the stackblock_size
						element.  Since it is the main thread we can
						assume the maximum available stack space.  */
					?: __MAX_ALLOCA_CUTOFF * 4));
}
```

We have to make sure that:

1. `size > PTHREAD_STACK_MIN / 4`
2. `size > MIN(__MAX_ALLOCA_CUTOFF, THREAD_GETMEM(THREAD_SELF, stackblock_size) / 4 ?: __MAX_ALLOCA_CUTOFF * 4)`
    * I did not fully understand what exactly the function - THREAD_GETMEM do, but it seems that it mostly returns 0.
    * Therefore, the second condition is usually `size > 65536`

More details:

* [__builtin_expect](https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html)
* [THREAD_GETMEM](https://code.woboq.org/userspace/glibc/sysdeps/x86_64/nptl/tls.h.html#_M/THREAD_GETMEM)


### conclusion

* The minimum size of width to trigger `malloc` & `free` is 65537 most of the time.
* If there is a Format String Vulnerability and the program ends right after calling `printf(buf)`, we can hijack `__malloc_hook` or `__free_hook` with `one-gadget` and use the trick mentioned above to trigger `malloc` & `free` then we can still get the shell even there is no more function call or sth after `printf(buf)`.

## Use execveat to open a shell

When it comes to opening a shell with system call, `execve` always pops up in mind. However, it's not always easily available due to the lack of gadgets or others constraints.  
Actually, there is a system call, `execveat`, with following prototype:

```c
int execveat(int dirfd, const char *pathname,
             char *const argv[], char *const envp[],
             int flags);
```

According to its [man page](http://man7.org/linux/man-pages/man2/execveat.2.html), it operates in the same way as `execve`. As for the additional arguments, it mentions that:

> If pathname is absolute, then dirfd is ignored.

Hence, if we make `pathname` point to `"/bin/sh"`, and set `argv`, `envp` and `flags` to 0, we can still get a shell whatever the value of `dirfd`.
