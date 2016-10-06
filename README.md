# stacksmash101

sort.c porgram has stack bufferflow vulnerabiloty which is exploited by the data.c file used to open a bash shell.


Simple stack buffer overflow exploitation (with simple examples of stack and heap overflow)


1.1 Stack overflow example 

/*
  StackOverrun.c
  This program shows an example of how a stack-based 
  buffer overrun can be used to execute arbitrary code.  Its 
  objective is to find an input string that executes the function bar.
*/
```
#pragma check_stack(off)

#include <string.h>
#include <stdio.h> 

void foo(const char* input)
{
    char buf[10];

    printf("My stack looks like:\n%p\n%p\n%p\n%p\n%p\n% p\n\n");

    strcpy(buf, input); //input is copied to buf until “/0” appears no check for input length

    printf("%s\n", buf);

    printf("Now the stack looks like:\n%p\n%p\n%p\n%p\n%p\n%p\n\n");
}

void bar(void)
{
    printf("Augh! I've been hacked!\n");
}

int main(int argc, char* argv[])
{
    //Blatant cheating to make life easier on myself
    printf("Address of foo = %p\n", foo);
    printf("Address of bar = %p\n", bar);
    if (argc != 2) 
 {
        printf("Please supply a string as an argument!\n");
        return -1;
	} 
foo(argv[1]);
    return 0;
}
```

In this example, buf[10] in the stack can be overflowed by providing an input much larger than 10 bytes


Any string input greater than 10 bytes(including the “\0”character)will overflow the stack 
11th, 12th,13th and 14th byte will overwrite the saved ebp value and next 4 more bytes overwrite the return address.

For exploit, the idea is to overwrite the return address to a value pointing to either on the stack somewhere or anywhere else in accessible memory space such that the attackers can force the program to do something unintended.

*from http://www.cse.scu.edu/~tschwarz/coen152_05/Lectures/BufferOverflow.html


1.2 Heap overflow example
```
#define BUFSIZE 32
int main(int argc, char **argv) {
char *buf,buf1;
buf = (char *)malloc(sizeof(char)*BUFSIZE);
buf1=(char*)malloc(sizeof(char)*BUFSIZE);
strcpy(buf, argv[1]);
free(buf1)
}
```
The Linux heap chunk definition looks like this:
```struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */

  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */




  struct malloc_chunk* fd;         /* double links -- used only if free. */

  struct malloc_chunk* bk;




  /* Only used for large blocks: pointer to next larger size.  */

  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */

  struct malloc_chunk* bk_nextsize;

};
 
```



the 33rd,34th,35th and 36th byte of argv overwrite prev_size of chunk 1 
similarly, next 4 bytes overwrite the size_chunk1 

Potential exploit: 
By overflowing buf, we can change the size_chunk1, (let’s say we increase it). 
Now when this chunk is freed, the next chunk will be consolidated with the previous chunk (chunk 0) using forward consolidation (ie using fd_next and bd_prev pointers). The next free chunks location is determined by adding size of chunk_1 to the current chunk address. This means that the attacker can actually jump in the middle of next chunk’s data. There It can plant its fake chunk. Using the capability of unlink method which actually does 4 byte writes into memory what an attacker can do is link his fake chunk (by using fake fd_next and bk_prev) with the actual list of currently used chunks. Practically giving him with a way to put anything in its own desired memory address.

*From: https://www.sans.edu/student-files/presentations/heap_overflows_notes.pdf


Attack on sort.c


Interesting thing to note is that after closing the shell it still goes into a segment trap because when we called the system function we gave an arbitrary value(0xb7e60000) as the address  to return which doesn’t exist. It means that someone who is checking the log dumps of this program run will know that function segment faulted at this address.
Instead if we give the address of exit function () address (0xb7e491e0) as the return address there will be error free exit. 
(I couldn’t achieve it because of the sort method making my stack always be in ascending order hence inserting smaller number at higher memory location was not possible) 


Some theory about code reuse attacks(Boring :P)

Code reuse attacks are those kind of attacks where the attacker doesn’t need to inject code explicitly to cause execution of unwanted lines of code or instructions. With use of data execution prevention schemes like WX code injection attacks are almost extinct now. But code reuse attacks work on the intuition that attacks can be carried out by reusing code that is already present in the address space of a user process, this maybe user defined functions used with dirty arguments or shared code in the code segment such as shared C library wrapper functions which perform system calls (return to libc). Some examples of code reuse attacks are  

o Return oriented: in this attacker basically can hijack the control flow of any program by executing combining chosen small instructions sequences called ‘gadgets’ that end with indirect branch statements like ret and combined together form a Turing complete instruction set. A classic example will be to find overwrite the stack buffer to overwrite the return address of a function call system(/bin/sh)

o Jump oriented: the attacker here doesn’t just have instructions ending with ret but also indirect jump statements. These gadgets may or may not be intended to be there but are present and can be used by an attacker to jump towards a target. Since there is no return they have to rely on dispatcher gadget to proceed forward and any register pointing to dispatcher table acts as the program counter.By gaining control of this dispatch table via dispatcher gadget an attacker can reach the target and load addresses on the way using load/ pop etc.

Defenses:  

Code Diversification aims at completely removing such intended or unintended gadgets in the memory space, if not make it probabilistically impossible for an attacker to guess where these gadgets are. 

For example ASLR(address space randomization) works with the idea that by randomizing the physical location of program and library code on every program run the attacker will have difficulty in knowing the address of desired function or gadgets apriori. But this defense is known to suffer from information leaks (brute force  in small entropy bit systems like 32 bits architecture or because of leaked pointers that give away base address)  such that if he attacker knows the address of any one function it’s easy to locate all functions (coarse grained randomization). Instruction Set Randomization comes with a high overhead.

A finer grained approach is to implement in place code randomization with the intuition that if all code blocks are rearranged in memory, then all the offsets of the gadgets that the attacker would think to be present in the code section of the process will not be valid. Similarly, binary stirring approach tries to randomize blocks of application/ user code thereby trying to mitigate code reuse. These techniques have been seen to cause less overhead however they are now seen to be ineffective against stronger attacks like an attacker with the ability to read or write to any arbitrary memory or side channel attacks which give away with randomized gadget address. They also seem to not work in programs that do just in time compilation(JIT).

Control Flow integrity is a technique to find possible execution path and creating a CFG graph and allowing control to flow by directed edges along the graph only. In theory this defense is sound enough but the realization is not so good. 
Firstly, most practical techniques don’t use the most restrictive CFG but instead use a bigger CFG than required for the program to function correctly, this is because of the high overhead of idea CFI. The tradeoff is that there have been recent attacks against these practical CFI. In fact attacks can be seen to be found against the ideal case of CFI too, which led to the concept of compartmentalization of memory into safe and normal section putting code pointers that can be used as possible gadgets to be placed in the secure section of memory called Code Pointer integrity(CPI). Side channel memory attacks like fault analysis (by observing program effects caused by abnormal input, example blind ROP attack) and timing analysis (use distinct input and measure the time taken to for processing that input) can disclose memory locations by using crash information in the first and non-crashing in the later.
                      
Possible counter measures include runtime re-randomization of the safe region, keyed hash functions for safe region and shrinking the size of safe region. The security benefits and overhead of these techniques is not so obvious.

