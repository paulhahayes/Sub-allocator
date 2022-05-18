////////////////////////////////////////////////////////////////////////////////
// COMP1521 22T1 --- Assignment 2: `Allocator', a simple sub-allocator        //
// <https://www.cse.unsw.edu.au/~cs1521/22T1/assignments/ass2/index.html>     //
//                                                                            //
// Written by YOUR-NAME-HERE (z5303576) on 23/04/2022                  //
//                                                                            //
// 2021-04-06   v1.0    Team COMP1521 <cs1521 at cse.unsw.edu.au>             //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "allocator.h"

// DO NOT CHANGE CHANGE THESE #defines

/** minimum total space for heap */
#define MIN_HEAP 4096

/** minimum amount of space to split for a free chunk (excludes header) */
#define MIN_CHUNK_SPLIT 32

/** the size of a chunk header (in bytes) */
#define HEADER_SIZE (sizeof(struct header))

/** constants for chunk header's status */
#define ALLOC 0x55555555
#define FREE 0xAAAAAAAA

// ADD ANY extra #defines HERE
#define MAX_SIZE 4294967292
#define VALID 1
#define INVALID 0
#define TRUE 1
#define FALSE 0
// DO NOT CHANGE these struct defintions

typedef unsigned char byte;

/** The header for a chunk. */
typedef struct header
{
    uint32_t status; /**< the chunk's status -- shoule be either ALLOC or FREE */
    uint32_t size;   /**< number of bytes, including header */
    byte data[];     /**< the chunk's data -- not interesting to us */
} header_type;

/** The heap's state */
typedef struct heap_information
{
    byte *heap_mem;         /**< space allocated for Heap */
    uint32_t heap_size;     /**< number of bytes in heap_mem */
    byte **free_list;       /**< array of pointers to free chunks */
    uint32_t free_capacity; /**< maximum number of free chunks (maximum elements in free_list[]) */
    uint32_t n_free;        /**< current number of free chunks */
} heap_information_type;

// Footnote:
// The type unsigned char is the safest type to use in C for a raw array of bytes
//
// The use of uint32_t above limits maximum heap size to 2 ** 32 - 1 == 4294967295 bytes
// Using the type size_t from <stdlib.h> instead of uint32_t allowing any practical heap size,
// but would make struct header larger.

// DO NOT CHANGE this global variable
// DO NOT ADD any other global  variables

/** Global variable holding the state of the heap */
static struct heap_information my_heap;

// ADD YOUR FUNCTION PROTOTYPES HERE
void merge_chunks(void *main_chunk, void *input_chunk);
int get_array_position(struct header *chunk);
int get_free_list_index(void *ptr);

// Initialise my_heap
int init_heap(uint32_t size)
{

    // Round input size up
    int remainder = size % 4;
    if (remainder != 0)
    {
        size = size - remainder + 4;
    }
    // Check requested size
    if (size < MIN_HEAP)
    {
        size = MIN_HEAP;
    }

    // Allocate a reduced size if it exceeds 32 bits
    if (size > MAX_SIZE)
    {
        size = MAX_SIZE;
    }

    // Update heap information
    int number_of_chunks = size / HEADER_SIZE;
    my_heap.heap_mem = malloc(size);
    if (my_heap.heap_mem == NULL)
    {
        return -1;
    }
    // Heap information countinued
    my_heap.heap_size = size;
    my_heap.free_capacity = number_of_chunks;
    my_heap.n_free = 1;
    my_heap.free_list = malloc(sizeof(byte *) * number_of_chunks);

    if (my_heap.free_list == NULL)
    {
        return -1;
    }

    // Create a header to the first free chunk
    struct header first_chunk;
    first_chunk.status = FREE;
    first_chunk.size = size;

    // Insert the header into the main memory array
    memcpy(my_heap.heap_mem, &first_chunk, HEADER_SIZE);

    // Update the free list pointers
    my_heap.free_list[0] = my_heap.heap_mem;

    return 0;
}

// Allocate a chunk of memory large enough to store `size' bytes
void *my_malloc(uint32_t size)
{

    // Check the requested size
    if (size < 1 || size + HEADER_SIZE > my_heap.heap_size)
    {
        return NULL;
    }
    // Round input size up to closest multiple of 4
    int remainder = size % 4;
    if (remainder != 0)
    {
        size = size - remainder + 4;
    }

    // If the rounded up value exceeds 32 bits, reduce it
    if (size > MAX_SIZE)
    {
        size = MAX_SIZE;
    }

    // Check if the heap is already full
    if (my_heap.n_free == 0)
    {
        return NULL;
    }

    // Begin to forfil the malloc request
    void *p = NULL;

    // Check each chunk in the heap
    for (int i = 0; i < my_heap.free_capacity; i++)
    {

        // Get chunks details in struct form
        struct header *chunk = (struct header *)my_heap.free_list[i];

        // Check if the current chunk can fit the request
        if (chunk->size >= size + HEADER_SIZE)
        {

            // Get an index value of my_heap.heap_mem array
            int position = get_array_position(chunk);

            // Make a new header
            struct header alloc_chunk_header;
            alloc_chunk_header.status = ALLOC;

            // TWO CASES
            // ALLOCATE THE WHOLE CHUNK
            if (chunk->size < size + HEADER_SIZE + MIN_CHUNK_SPLIT)
            {

                // Update the chunk's information
                alloc_chunk_header.size = chunk->size;
                memcpy(my_heap.heap_mem + position, &alloc_chunk_header, HEADER_SIZE);
                my_heap.n_free -= 1;

                // Starting at the current pointer, shift the free_list pointers one address to the right
                for (int current_pointer = i; current_pointer < my_heap.free_capacity - 1; current_pointer++)
                {
                    my_heap.free_list[current_pointer] = my_heap.free_list[current_pointer + 1];
                }

                // Provide a return value of the requested malloc data for the user
                p = &my_heap.heap_mem[position + HEADER_SIZE];
            }
            // SPLIT THE CHUNK
            else
            {

                // The chunk will be split into a free and allocated part

                // Create the free part
                struct header free_header;
                free_header.status = FREE;
                // The free part will be the remainder of the chunk
                free_header.size = chunk->size - (size + HEADER_SIZE);
                // Update the heap information
                memcpy(my_heap.heap_mem + size + position + HEADER_SIZE, &free_header, HEADER_SIZE);
                my_heap.free_list[i] = &my_heap.heap_mem[position + size + HEADER_SIZE];

                // Create that alloc part
                alloc_chunk_header.size = size + HEADER_SIZE;
                alloc_chunk_header.status = ALLOC;
                // Update the heap information
                memcpy(my_heap.heap_mem + position, &alloc_chunk_header, HEADER_SIZE);

                // Provide a return value of the requested malloc data for the user
                p = &my_heap.heap_mem[position + HEADER_SIZE];
            }
            break;
        }
    }

    return p;
}

// Deallocate chunk of memory referred to by `ptr'
void my_free(void *ptr)
{

    // Check the input ptr has data
    if (ptr == NULL)
    {
        fprintf(stderr, "%s", "Attempt to free unallocated chunk\n");
        exit(1);
    }

    // Reposition the pointer to its associated chunk header
    ptr = ptr - HEADER_SIZE;
    struct header *chunk = (struct header *)ptr;

    // Function variables
    int checker = INVALID;
    int no_offset = TRUE;
    int memory_position = 0;
    void *left_offset = ptr;
    struct header *memory_position_finder = (struct header *)(my_heap.heap_mem + memory_position);

    // Iterate over the memory chunks to check that the input ptr is valid
    for (int i = 0; i < my_heap.free_capacity; i++)
    {

        // The input pointer has been found
        if (memory_position_finder == (struct header *)ptr)
        {
            checker = VALID;
            break;
        }

        // Iterate
        // left offset might be used for defragmentation
        left_offset = memory_position_finder;
        memory_position += memory_position_finder->size;
        memory_position_finder = (struct header *)(my_heap.heap_mem + memory_position);
    }

    // Checks that the input ptr was valid and not already free
    if (checker != VALID || chunk->status == FREE)
    {
        fprintf(stderr, "%s", "Attempt to free unallocated chunk\n");
        exit(1);
    }

    // Now, since the input ptr is valid
    // Count the number of free pointers
    int free_list_index = get_free_list_index(ptr);

    // Set the chunk to free and erase its data
    chunk->status = FREE;
    void *clear_data[chunk->size];
    memcpy(my_heap.heap_mem + memory_position + HEADER_SIZE, &clear_data, chunk->size - HEADER_SIZE);
    my_heap.n_free += 1;

    // DEFRAGMENTATIONS CHECKS

    // RIGHT CHUNK CHECK
    // chunk->size + memory_position is the RHS edge of the array
    // which cannot be check as a struct
    if (chunk->size + memory_position != my_heap.heap_size)
    {

        // Create a pointer to the chunk to the right of the input chunk
        void *right_offset = ptr + chunk->size;
        struct header *right_header = (struct header *)right_offset;

        // Check the chunk's status
        if (right_header->status == FREE)
        {

            // Since they are both free, combine them
            merge_chunks(ptr, right_offset);
            my_heap.free_list[free_list_index] = ptr;
            no_offset = FALSE;
        }
    }
    // LEFT CHUNK CHECK
    // If position is zero then the array won't have any memory to its left
    if (memory_position != 0)
    {
        // Create a pointer to the chunk to the left of the input chunk
        struct header *left_header = (struct header *)left_offset;
        // Check its status
        if (left_header->status == FREE)
        {

            // Since they are both free combine them
            merge_chunks(left_offset, ptr);
            no_offset = FALSE;
        }
    }

    // If the left and right of the input chunk are allocated, then
    // free the input chunk and shift the free_pointer list right to make space
    if (no_offset == TRUE)
    {
        for (int j = free_list_index; j < my_heap.free_capacity - 1; j++)
        {
            my_heap.free_list[j + 1] = my_heap.free_list[j];
        }
        my_heap.free_list[free_list_index] = ptr;
    }

    return;
}

// DO NOT CHANGE CHANGE THiS FUNCTION
//
// Release resources associated with the heap
void free_heap(void)
{
    free(my_heap.heap_mem);
    free(my_heap.free_list);
}

// DO NOT CHANGE CHANGE THiS FUNCTION

// Given a pointer `obj'
// return its offset from the heap start, if it is within heap
// return -1, otherwise
// note: int64_t used as return type because we want to return a uint32_t bit value or -1
int64_t heap_offset(void *obj)
{
    if (obj == NULL)
    {
        return -1;
    }
    int64_t offset = (byte *)obj - my_heap.heap_mem;
    if (offset < 0 || offset >= my_heap.heap_size)
    {
        return -1;
    }

    return offset;
}

// DO NOT CHANGE CHANGE THiS FUNCTION
//
// Print the contents of the heap for testing/debugging purposes.
// If verbosity is 1 information is printed in a longer more readable form
// If verbosity is 2 some extra information is printed
void dump_heap(int verbosity)
{

    if (my_heap.heap_size < MIN_HEAP || my_heap.heap_size % 4 != 0)
    {
        printf("ndump_heap exiting because my_heap.heap_size is invalid: %u\n", my_heap.heap_size);
        exit(1);
    }

    if (verbosity > 1)
    {
        printf("heap size = %u bytes\n", my_heap.heap_size);
        printf("maximum free chunks = %u\n", my_heap.free_capacity);
        printf("currently free chunks = %u\n", my_heap.n_free);
    }

    // We iterate over the heap, chunk by chunk; we assume that the
    // first chunk is at the first location in the heap, and move along
    // by the size the chunk claims to be.

    uint32_t offset = 0;
    int n_chunk = 0;
    while (offset < my_heap.heap_size)
    {
        struct header *chunk = (struct header *)(my_heap.heap_mem + offset);

        char status_char = '?';
        char *status_string = "?";
        switch (chunk->status)
        {
        case FREE:
            status_char = 'F';
            status_string = "free";
            break;

        case ALLOC:
            status_char = 'A';
            status_string = "allocated";
            break;
        }

        if (verbosity)
        {
            printf("chunk %d: status = %s, size = %u bytes, offset from heap start = %u bytes",
                   n_chunk, status_string, chunk->size, offset);
        }
        else
        {
            printf("+%05u (%c,%5u) ", offset, status_char, chunk->size);
        }

        if (status_char == '?')
        {
            printf("\ndump_heap exiting because found bad chunk status 0x%08x\n",
                   chunk->status);
            exit(1);
        }

        offset += chunk->size;
        n_chunk++;

        // print newline after every five items
        if (verbosity || n_chunk % 5 == 0)
        {
            printf("\n");
        }
    }

    // add last newline if needed
    if (!verbosity && n_chunk % 5 != 0)
    {
        printf("\n");
    }

    if (offset != my_heap.heap_size)
    {
        printf("\ndump_heap exiting because end of last chunk does not match end of heap\n");
        exit(1);
    }
}

// ADD YOUR EXTRA FUNCTIONS HERE

// Given two chunks of memory, this function combines them into a single block
void merge_chunks(void *main_chunk, void *input_chunk)
{

    struct header *main_header = (struct header *)main_chunk;
    struct header *input_header = (struct header *)input_chunk;
    main_header->size += input_header->size;
    input_chunk = main_chunk;
    my_heap.n_free -= 1;

    return;
}

// Given a chunk of memory, this function returns an int value of
// Where the ptr is in the my_heap.heap_mem array
int get_array_position(struct header *chunk)
{

    int position = 0;
    // start at begining of the memory array
    struct header *position_finder = (struct header *)(my_heap.heap_mem + position);
    while (position_finder != chunk)
    {

        position += position_finder->size;
        position_finder = (struct header *)(my_heap.heap_mem + position);
    }
    return position;
}

// Given a ptr to a spot in the memory array, this function counts How
// many free chunks there are between the start of the array and the ptr
int get_free_list_index(void *ptr)
{
    int memory_position = 0;
    int free_list_index = 0;
    struct header *memory_position_finder = (struct header *)(my_heap.heap_mem + memory_position);

    for (int i = 0; i < my_heap.free_capacity; i++)
    {

        // As we traverse the memory,
        // Keep track of how many FREE ptrs we have checked

        if (memory_position_finder->status == FREE)
        {
            free_list_index++;
        }
        if (memory_position_finder == (struct header *)ptr)
        {
            break;
        }
        memory_position += memory_position_finder->size;
        memory_position_finder = (struct header *)(my_heap.heap_mem + memory_position);
    }
    return free_list_index;
}
