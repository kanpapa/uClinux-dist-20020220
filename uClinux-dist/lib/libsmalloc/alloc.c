/****************************************************************************/
/*
 * lib/libc/malloc-slow
 *
 *	A simple freelist style allocator with no adjacent block combining
 *	or anything.  The whole purpose is to make very efficient use of
 *	paged memory that the kernel provides for us.  This code knows about
 *	kmalloc and how it aligns its pages (power of 2 plus a bit).  To make
 *	this code work well you will need to adjust the PAGE_SIZE and
 *	ALLOC_COST macros to match your kmalloc/mmap setup.  The current ones
 *	are configured for uClinux.
 *
 *	PROBLEMS:
 *		It never actually frees memory,  which is bad if you allocate a lot
 *		then free it all without exiting.  It does re-use freed memory
 *		which is better than nothing.
 *
 *	Copyright (C) 2000, Lineo Australia
 *	davidm@lineo.com
 */
/****************************************************************************/

#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>

/****************************************************************************/
/*
 *	the page size of this kernel
 */

#define	PAGE_SIZE	4096

/*
 *	the cost of using mmap to allocate a page (ie., PAGE_SIZE - ALLOC_COST
 *	wil result in a single page allocation
 */

#define	ALLOC_COST	24

/****************************************************************************/
/*
 *	kernel allocations go up in powers of 2
 */

#ifdef L_malloc

static int blocksizes[] = {
	(PAGE_SIZE << 0) - ALLOC_COST,
	(PAGE_SIZE << 1) - ALLOC_COST,
	(PAGE_SIZE << 2) - ALLOC_COST,
	(PAGE_SIZE << 3) - ALLOC_COST,
	(PAGE_SIZE << 4) - ALLOC_COST,
	(PAGE_SIZE << 5) - ALLOC_COST,
	(PAGE_SIZE << 6) - ALLOC_COST,
	(PAGE_SIZE << 7) - ALLOC_COST,
	(PAGE_SIZE << 8) - ALLOC_COST,
	(PAGE_SIZE << 9) - ALLOC_COST,
	(PAGE_SIZE << 10) - ALLOC_COST,
	(PAGE_SIZE << 11) - ALLOC_COST,
	(PAGE_SIZE << 12) - ALLOC_COST,
	(PAGE_SIZE << 13) - ALLOC_COST,
	(PAGE_SIZE << 14) - ALLOC_COST,
	(PAGE_SIZE << 15) - ALLOC_COST,
	0
};

#endif

/*
 *	A simple low cost free list
 */

struct free_list {
	long size;
	struct free_list *next;
};

#ifdef L_malloc
struct free_list *__malloc_free_list = NULL;
#else
extern struct free_list *__malloc_free_list;
#endif

/****************************************************************************/
#ifdef L_malloc
/*
 *	Ye olde favourite
 */

void *
malloc(size_t size)
{
	void *memory;
	int	i;
	static void *current_block = NULL;
	static long	 current_space = 0;

/*
 *	so that everything stays correctly aligned we must only
 *	allocate multiples of 4 bytes, we also do it to make sure
 *	we have enough space to store the free list structure (8 bytes total)
 */
	size = (size + 3) & ~0x3;

	if (__malloc_free_list) {
		struct free_list **f, **best_fit = NULL;

		f = &__malloc_free_list;
		while (*f) {
			if ((*f)->size >= size) {
				if (!best_fit || (*f)->size < (*best_fit)->size)
					best_fit = f;
				if ((*best_fit)->size == size)
					break;
			}
			f = &(*f)->next;
		}

		if (best_fit) {
			memory = *best_fit;
			*best_fit = (*best_fit)->next;
			return(((long *) memory) + 1);
		}
	}

	for (i = 0; blocksizes[i]; i++)
		if (blocksizes[i] > size + sizeof(long))
			break;

	if (blocksizes[i] == 0)
		return(NULL);

	if (current_space < size + sizeof(long)) {
		struct free_list *f;

		if (current_space >= sizeof(struct free_list)) {
			f = current_block;
			f->size = current_space - sizeof(long);
			f->next = __malloc_free_list;
			__malloc_free_list = f;
		}
		current_block = sbrk(size + sizeof(long));
		if (current_block == (void *) -1) {
			current_block  = mmap((void *) 0, blocksizes[i],
					PROT_READ | PROT_WRITE,
#ifdef EMBED
					MAP_SHARED | MAP_ANONYMOUS,
#else
					MAP_PRIVATE | MAP_ANONYMOUS,
#endif
					0, 0);
			if (current_block == (void *) -1) {
				current_block = NULL;
				return(NULL);
			}
			current_space = blocksizes[i];
		} else
			current_space = size + sizeof(long);
	}
	memory = current_block;
	* ((long *) memory) = size;
	current_block = ((char *) current_block) + (size + sizeof(long));
	current_space -= (size + sizeof(long));

	return(((long *) memory) + 1);
}

#endif
/****************************************************************************/
#ifdef L_calloc
/*
 *	Send everything through else malloc (this is slow malloc ;-)
 */

void *
calloc(size_t num, size_t size)
{
  void *memory = malloc(num * size);
  if (memory)
  	memset(memory, 0, num * size);
  return(memory);
}

#endif
/****************************************************************************/
#ifdef L_realloc
/*
 *	Try to be smarter about re-allocs
 */

void *
realloc(void *ptr, size_t size)
{
	long *mem = ptr;

	if (!ptr)
		return(malloc(size));
/*
 *	if this block is big enough,  just return it
 */
	if (size <= mem[-1])
		return(ptr);

	mem = malloc(size);
	memcpy(mem, ptr, size);
	free(ptr);
	return((void *) mem);
}

#endif
/****************************************************************************/
#ifdef L_free
/*
 *	Put the memory on the free list
 */

void
free(void *ptr)
{
    if(ptr) {
	long	*mem = ptr;
	struct free_list *f = (struct free_list *) (mem - 1);
	f->next = __malloc_free_list;
	__malloc_free_list = f;
    }
}

#endif
/****************************************************************************/
