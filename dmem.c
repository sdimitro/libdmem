/*
 * Copyright 2019 Delphix
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * = Printing From Within The Library
 *
 * There are implementations of libc where printf and friends do heap
 * allocations. For this reason, we implement our own version of them
 * that don't allocate anything on the heap (e.g. no calls to malloc())
 * to eliminate all scenarios of deadlocks, boundless recursion, and
 * SEGFAULTS due to calling our malloc() while initializing or using
 * it. Even if all these problems are solveable (we do solve many of
 * them in the initialization code later - dmem_init()) it would still
 * be annoying attempting to differentiate correctly between allocations
 * happening outside and inside of the library through our public
 * interfaces (e.g. main program calls our malloc() which returns a
 * pointer [normal allocation] but our malloc() prints to stderr for
 * debugging purposes by calling printf() which calls into malloc()
 * again [internal allocation]). A lot of the code for these functions
 * has been borrowed by libvmem mentioned later that is published under
 * the same license.
 */
#define DMEM_PRINT_BUF 1024
#define DMEM_PRINT_LOG 8192

char dmem_panicstr[DMEM_PRINT_BUF];
char dmem_print_log[DMEM_PRINT_LOG + DMEM_PRINT_BUF];

static void
__attribute__((format(printf, 1, 0)))
dmem_vprintf(const char *fmt, va_list va)
{
	int saved_errno = errno;
	static size_t dmem_print_log_idx = 0;

	char buf[DMEM_PRINT_BUF];
	buf[0] = '\0';
	(void) vsnprintf(buf, sizeof (buf), fmt, va);

	size_t len = strlen(buf);
	size_t idx = __sync_fetch_and_add(&dmem_print_log_idx, len);
	bcopy(buf, &dmem_print_log[idx % DMEM_PRINT_LOG], len);

	(void) write(fileno(stderr), buf, strlen(buf));
	errno = saved_errno;
}

static void
__attribute__((format(printf, 1, 2)))
dmem_printf(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	dmem_vprintf(fmt, va);
	va_end(va);
}

static void
__attribute__((noreturn))
__attribute__((format(printf, 1, 0)))
dmem_vpanic(const char *fmt, va_list va)
{
	int saved_errno = errno;
	static pthread_mutex_t dmem_panic_lock;
	(void) pthread_mutex_lock(&dmem_panic_lock);

	(void) vsnprintf(dmem_panicstr, sizeof (dmem_panicstr) - 1, fmt, va);
	(void) strcat(dmem_panicstr, "\n");
	(void) write(fileno(stderr), dmem_panicstr, strlen(dmem_panicstr));

	errno = saved_errno;
	abort();
}

static void
__attribute__((noreturn))
__attribute__((format(printf, 1, 2)))
dmem_panic(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	dmem_vpanic(fmt, va);
	va_end(va);
}

#define DMEM_OPT_STR "DMEM_OPTS"
#define DMEM_OPT_LEN 512

typedef struct dmem_opt {
	const char *opt_name;
	size_t *opt_valp;
} dmem_opt_t;

static size_t dmem_log_all = 0;
static size_t dmem_findleaks = 0;

static void
dmem_options_parse()
{
	const char *envstr = getenv(DMEM_OPT_STR);
	if (envstr == NULL)
		return;

	size_t envstr_len = strlen(envstr);
	if (envstr_len > DMEM_OPT_LEN) {
		dmem_panic("dmem_options_parse(): %s passed is "
			"%ld characters (limit: %d)\n",
			DMEM_OPT_STR, envstr_len, DMEM_OPT_LEN);
	}

	char *str = alloca(strlen(envstr) + 1);
	(void) strcpy(str, envstr);

	dmem_opt_t options[] = {
		{ "log-all", &dmem_log_all },
		{ "report-leaks", &dmem_findleaks },
	};
	dmem_opt_t *options_end = (void *)options + sizeof (options);

	char *opt = NULL;
	while ((opt = strsep(&str, ",")) != NULL) {
		for (dmem_opt_t *o = options; o < options_end; o++) {
			if (strcmp(o->opt_name, opt) == 0) {
				*o->opt_valp = 1;
			}
		}
	}
}

/*
 * = Tracking Allocations
 *
 * We track allocated segments by asking the underlying malloc()
 * implementation for slightly larger segments so we can prepend
 * each segment with a tag (dmem_alloc_entry_t) that we use to
 * implement the majority of our functionality. The tag's most
 * basic job is to link together all segments in a doubly-linked
 * list.
 *
 * The main advantages of this approach are:
 * - Metadata access and retrieval operations for each segment
 *   are O(1).
 * - There is no need for separate calls to malloc() as data
 *   and metadata are bundled together.
 *
 * The main disadvantages are:
 * - The pointers that we get and return to the user cannot be
 *   passed as-is to the underlying malloc() because of our tags.
 *   Generally speaking that shouldn't be a problem assuming
 *   we've covered all the malloc() family, but we could blow
 *   up on scenarios where the application tries to do something
 *   *smart*.
 * - We can't track anything about frees.
 */
typedef struct dmem_alloc_entry {
	struct dmem_alloc_entry *next;
	struct dmem_alloc_entry *prev;
} dmem_alloc_entry_t;

static dmem_alloc_entry_t dmem_alloc_list_head = {
	.next = &dmem_alloc_list_head,
	.prev = &dmem_alloc_list_head,
};

static pthread_mutex_t dmem_alloc_list_lock;

static uint64_t dmem_metadata_bytes = 0;

static inline size_t
__attribute__((always_inline))
__attribute__((pure))
dmem_alloc_entry_full_size(size_t payload_size)
{
	return (payload_size + sizeof (dmem_alloc_entry_t));
}

static inline dmem_alloc_entry_t *
__attribute__((always_inline))
__attribute__((pure))
dmem_alloc_entry_get_from_ptr(void *ptr)
{
	return (ptr - sizeof(dmem_alloc_entry_t));
}

static inline void *
__attribute__((always_inline))
__attribute__((pure))
dmem_alloc_entry_get_ptr(dmem_alloc_entry_t *dae)
{
	return ((void *)((uintptr_t)dae) + sizeof(dmem_alloc_entry_t));
}

static void
dmem_alloc_entry_add(dmem_alloc_entry_t *dae)
{
	(void) pthread_mutex_lock(&dmem_alloc_list_lock);

	dae->next = dmem_alloc_list_head.next;
	dae->next->prev = dae;
	dae->prev = &dmem_alloc_list_head;
	dmem_alloc_list_head.next = dae;

	dmem_metadata_bytes += sizeof (dmem_alloc_entry_t);

	(void) pthread_mutex_unlock(&dmem_alloc_list_lock);
}

static void
dmem_alloc_entry_remove(dmem_alloc_entry_t *dae)
{

	(void) pthread_mutex_lock(&dmem_alloc_list_lock);

	dae->next->prev = dae->prev;
	dae->prev->next = dae->next;

	dmem_metadata_bytes -= sizeof (dmem_alloc_entry_t);

	(void) pthread_mutex_unlock(&dmem_alloc_list_lock);
}

static void
dmem_alloc_report_leaks()
{
	uint64_t nleaks = 0;
	for (dmem_alloc_entry_t *e = dmem_alloc_list_head.next;
	    e != &dmem_alloc_list_head; e = e->next) {
		if (dmem_log_all) {
			dmem_printf("libdmem: leaked: %p\n",
			    dmem_alloc_entry_get_ptr(e));
		}
		nleaks++;
	}

	if (nleaks == 0)
		return;

	dmem_printf("libdmem: # leaks found - %ld\n", nleaks);
}


/*
 * = Interposition Of Functions and Initialization
 *
 * We want to be able to do the following:
 *
 * [1] Interpose our malloc to be used in-place of any other malloc loaded
 *     at runtime (not need for special compilation or linking).
 * [2] Call the original malloc function (aka "backend" malloc) from our
 *     malloc.
 *
 * Similarly for realloc, calloc, and free.
 *
 * The issues that we face are:
 *
 * [1] Being able to load our code and use it before anything else. E.g.
 *     we want all mallocs from the loading of a program to its execution
 *     to use our version of the function.
 * [2] Attempting to allocate memory through our initialization function
 *     [dmem_init()]. We create a chicken-and-the-egg problem when we
 *     want all malloc() calls to user our malloc but in order for our
 *     malloc() function to work we need to allocated memory - a good
 *     example of this is the calls to malloc() that take place in the
 *     dlsym() calls in dmem_init(). Our mallocs need dmem_init() to
 *     run first but when dmem_init() runs, it calls dlsym() which can
 *     call back to malloc().
 * [3] Another shared library having its initialization/constructor code
 *     ran before our library is initialized, and that library's code
 *     calls malloc().
 *
 * LD_PRELOAD is the standard method to deal with [1] but it creates [2]
 * and [3]. Making dmem_init() (the initialization code) run as the
 * constructor of our shared library (e.g. ran before main()) deals with
 * some scenarios of [2] but not all, and does nothing for [3]. This is
 * why the following process is used:
 *
 * - dmem_init() is declared as a constructor but it can also be called
 *   by any of our public functions (malloc(), free(), etc...) if one
 *   of these functions is called as part of a constructor of another
 *   shared library (deals with problem [3]).
 * - Once dmem_init() starts running it may call one of our public
 *   functions as part of its initialization process (see dlsym()
 *   problem [2]). For that reason we have the `initialization` global
 *   variable that is set when dmem_init() starts running. When this
 *   global is set all of our public functions enter an alternative
 *   code path where they think that they are allocating space but
 *   they actually carve pieces from a predefined buffer. The idea
 *   is to satisfy this initial allocations needed for our library
 *   until the initialization step is done. For more info see `init_buf`
 *   (global variable), `init_{malloc,calloc,realloc,free}` and
 *   `dmem_init()`.
 * - Once initialization is done, the `initialization` global variable
 *   is set to 0, our backend functions have been detected, and we are
 *   ready to start serving malloc() calls and friends for the main
 *   process.
 *
 * Note that like the rest of the current code in this library, the
 * initialization step wouldn't work in a concurrent settings as it
 * currently has no locks to guard its internal structures.
 */

/*
 * Predefined buffer and pointer to its current end for the allocations
 * happening within dmem_init(). The buffer is zero-ed out at declaration
 * to follow the semantics of calloc() right away. Keep in mind that we
 * never actually free anything in that buffer - init_free() is a no-op.
 */
#define INIT_BUFSIZE (4 * 1024)
static char init_buf[INIT_BUFSIZE] = {0};

static void *
init_malloc(size_t size)
{
	static size_t init_buf_idx = 0;

	size_t idx = __sync_fetch_and_add(&init_buf_idx, size);
	assert(idx + size < sizeof(init_buf));
	void *retp = init_buf + idx;
	return retp;
}

static void *
init_calloc(size_t nelem, size_t size)
{
	return init_malloc(nelem * size);
}

static void *
init_realloc(void *ptr, size_t size)
{
	char *newp = init_malloc(size);
	/*
	 * This is by no means secure nor "proper" but it doesn't violate
	 * any of the semantics of calloc and given our use-case the fact
	 * that it copies extra data (potentially from neighboring segments)
	 * hopefully will never matter.
	 */
	(void) memmove(newp, ptr, size);
	return newp;
}

void
init_free(void *ptr)
{
	/* no-op */
}


static void *
dmem_dlsym(char *sym)
{
	dlerror(); /* clear any existing errors before dlsym() call  */
	void *loaded_sym = dlsym(RTLD_NEXT, sym);
	char *dlerr = dlerror();
	if (dlerr != NULL) {
		dmem_panic("dmem: dmem_dlsym(%s): %s\n", sym, dlerr);
	}
	return loaded_sym;
}

static bool initialization = false;
static void* (*backend_malloc)(size_t) = NULL;
static void* (*backend_calloc)(size_t, size_t) = NULL;
static void* (*backend_free)(void *) = NULL;
static void* (*backend_realloc)(void *, size_t) = NULL;

static void
__attribute__((constructor))
dmem_init()
{
	if (backend_malloc != NULL) {
		assert(backend_calloc != NULL);
		assert(backend_free != NULL);
		assert(backend_realloc != NULL);
		return;
	}

	assert(!initialization);
	initialization = true;

	assert(backend_calloc == NULL);
	assert(backend_free == NULL);
	assert(backend_realloc == NULL);

	backend_malloc = dmem_dlsym("malloc");
	backend_free = dmem_dlsym("free");
	backend_calloc = dmem_dlsym("calloc");
	backend_realloc = dmem_dlsym("realloc");

	dmem_options_parse();

	initialization = false;
}

static void
__attribute__((destructor))
dmem_fini()
{
	if (dmem_findleaks) {
		dmem_alloc_report_leaks();
	}
}

void *
malloc(size_t size)
{
	if (initialization) {
		return init_malloc(size);
	} else if (backend_malloc == NULL) {
		dmem_init();
	}

	size_t dmem_size = size;
	if (dmem_findleaks) {
		dmem_size = dmem_alloc_entry_full_size(size);
	}

	void *p = backend_malloc(dmem_size);

	if (dmem_findleaks) {
		dmem_alloc_entry_add(p);
		p = dmem_alloc_entry_get_ptr(p);
	}

	if (dmem_log_all)
		dmem_printf("malloc(%ld) = %p\n", size, p);
	return p;
}

void *
calloc(size_t nelem, size_t size)
{
	if (initialization) {
	    return init_calloc(nelem, size);
	} else if (backend_calloc == NULL) {
		dmem_init();
	}

	size_t dmem_nelem = nelem, dmem_size = size;
	if (dmem_findleaks) {
		/*
		 * The following logic was implemented as a placeholder
		 * until we come up with something better and has the
		 * following problems:
		 *
		 * [1] If we have a lot of small elements the memory
		 *     overhead incured can be severe (e.g. 1000
		 *     4-byte elements, normally around ~4KB, would
		 *     now consume ~20KB which is 5x more).
		 *
		 * [2] The memory overhead will also be severe for
		 *     elements that are too big (e.g. allocating
		 *     one 1MB element, would consume 2MBs now).
		 */
		size_t metadata_size = sizeof (dmem_alloc_entry_t);
		if (size < metadata_size) {
			dmem_size = metadata_size;
		} else {
			dmem_nelem += 1;
		}
	}

	void *p = backend_calloc(dmem_nelem, dmem_size);

	if (dmem_findleaks) {
		dmem_alloc_entry_add(p);
		p = dmem_alloc_entry_get_ptr(p);
	}

	if (dmem_log_all)
		dmem_printf("calloc(%ld, %ld) = %p\n", nelem, size, p);
	return p;
}

void *
realloc(void *ptr, size_t size)
{
	if (initialization) {
	    return init_realloc(ptr, size);
	} else if (backend_realloc == NULL) {
		dmem_init();
	}

	void *dmem_ptr = ptr;
	size_t dmem_size = size;
	if (dmem_findleaks) {
		/*
		 * It is possible that a consumer supplies a NULL
		 * pointer to realloc() in which case it's supposed
		 * to work like malloc().
		 */
		if (ptr != NULL) {
			dmem_ptr = dmem_alloc_entry_get_from_ptr(ptr);
			dmem_alloc_entry_remove(dmem_ptr);
		}
		dmem_size = dmem_alloc_entry_full_size(size);
	}

	void *p = backend_realloc(dmem_ptr, dmem_size);

	/*
	 * It is possible that a consumer supplies 0 as the
	 * size to realloc() in which case it's supposed to
	 * work like free().
	 */
	if (dmem_findleaks && size > 0) {
		dmem_alloc_entry_add(p);
		p = dmem_alloc_entry_get_ptr(p);
	}

	if (dmem_log_all)
		dmem_printf("realloc(%p, %ld) = %p\n", ptr, size, p);
	return p;
}

void
free(void *ptr)
{
	if (ptr == NULL)
		return;

	if (initialization) {
	    init_free(ptr);
	    return;
	} else if (backend_free == NULL) {
		dmem_init();
	}

	void *dmem_ptr = ptr;
	if (dmem_findleaks) {
		dmem_ptr = dmem_alloc_entry_get_from_ptr(ptr);
		dmem_alloc_entry_remove(dmem_ptr);
	}

	backend_free(dmem_ptr);

	if (dmem_log_all)
		dmem_printf("free(%p)\n", ptr);
}
