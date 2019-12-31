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
 * has been borrowed by libvmem referenced below that is published under
 * the same license.
 * - libvmem: github.com/thecodeteam/dssd/blob/master/lib/libvmem
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

/*
 * = Miscellaneous Wrappers
 */
static void *
dmem_dlsym_impl(void *handle, char *sym)
{
	/*
	 * Clear any existing errors before dlsym() call
	 */
	dlerror();

	void *loaded_sym = dlsym(handle, sym);
	char *dlerr = dlerror();
	if (dlerr != NULL) {
		dmem_panic("dmem: dmem_dlsym(%s): %s\n", sym, dlerr);
	}

	return loaded_sym;
}

static void *
dmem_dlsym(char *sym)
{
	return dmem_dlsym_impl(RTLD_NEXT, sym);
}


static void *
dmem_dlopen(char *shared_obj)
{
	/*
	 * Clear any existing errors before dlsym() call
	 */
	dlerror();

	void *handle = dlopen (shared_obj, RTLD_LAZY);
	char *dlerr = dlerror();
	if (dlerr != NULL) {
		dmem_panic("dmem: dmem_dlopen(%s): %s\n", shared_obj, dlerr);
	}

	return handle;
}

/*
 * = Runtime Configuration Through DMEM_OPTS
 */
#define DMEM_OPT_STR "DMEM_OPTS"
#define DMEM_OPT_LEN 512

typedef struct dmem_opt {
	const char *opt_name;
	size_t *opt_valp;
} dmem_opt_t;

static size_t dmem_trace_stderr = 0;
static size_t dmem_log_allocs = 0;
static size_t dmem_abort_on_shutdown = 0;

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
		{ "trace-stderr", &dmem_trace_stderr },
		{ "log-allocs", &dmem_log_allocs },
		{ "abort-shutdown", &dmem_abort_on_shutdown },
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
 * = Recording The Stack Traces of Allocations
 *
 * At times we may want to record the stack traces at which allocations
 * occur like when we want to see where a memory leak came from or which
 * part of our code allocates the most memory. In this current iteration
 * of libdmem we reserve extra space with our tags for that exact reason,
 * to store the program counters that are part of the stack for each
 * allocation (currently we limit that stack trace to a specific amount
 * of frames to control the space overhead of our tags - refer to
 * DMEM_TX_MAX_STACK_DEPTH for details). It also saves the thread pointer
 * of the thread that did the allocation, which can be helpful for
 * multithreaded apps (assuming they are using pthreads as their threading
 * mechanism).
 *
 * There are multiple tradeoffs involved in deciding on how to properly
 * record a backtrace:
 *
 * [1] Use __builtin_return_address provided by the GCC compiler runtime
 *     (see https://gcc.gnu.org/onlinedocs/gcc/Return-Address.html). The
 *     problem is that this approach requires all the code on the stack
 *     to have been compiled with the same GCC options which is unlikely.
 * [2] Use the debugger runtime, like glibc's backtrace(3). The issue
 *     with this is that by default calls to malloc() are made which would
 *     be problematic for our use-case.
 * [3] Use the ABI. Solaris and illumos provide a frame structure with
 *     specific stack alignment and routines to determine the current
 *     thread stack. Unfortunately, none of this is available to Linux.
 * [4] Supply -fno-omit-frame-pointer as an option at compile time for
 *     libdmem AND any program/library that will be debugged by it.
 *     Then use __builtin_frame_address(0) from libdmem to return the
 *     correct starting point and go from there. This can be thought as
 *     a variation of [1] and it is a bit against our attempt to try to
 *     use libdmem in a wide-range of situations.
 *
 * With the above in mind, I spend some time examining solution [2] further
 * and seeing the places where the memory allocations took place and see if
 * I can avoid them and at first glance I believe I was able to do so. The
 * main allocation that I could find happening from backtrace(3) was from
 * the call to dlopen() and the subsequent calls to dlsym() on the first time
 * the fuction was called. Examining its code further those seems to have
 * originated by lazily initializing the function pointers to the following
 * functions from the GCC runtime: _Unwind_Backtrace() & _Unwind_GetIP().
 * No further allocations seemed to have taken place. Thus, I decided to
 * basically implement a variant of backtrace(3) which strictly loads the
 * above two function during the initialization of libdmem and have their
 * dlsym() calls allocate memory from the init buffer of libdmem.
 */
#define DMEM_TX_MAX_STACK_DEPTH 11

typedef struct dmem_tx {
	pthread_t dt_thread;
	void *dt_stack[DMEM_TX_MAX_STACK_DEPTH];
} dmem_tx_t;

#define LIBGCC_S_SO "libgcc_s.so.1"
static void* dmem_libgcc_s_hdl = NULL;

/*
 * Note that for the backend functions below the actual return
 * types and some of the argument types are not void pointers
 * but we declare them as such because its easy and because
 * they are private data that we don't care about.
 */
static void* (*backend_unwind_backtrace)(void *, void *) = NULL;
static void* (*backend_unwind_get_ip)(void *) = NULL;

static void
dmem_load_unwind_backtrace()
{
	assert(dmem_libgcc_s_hdl == NULL);
	assert(backend_unwind_backtrace == NULL);
	assert(backend_unwind_get_ip == NULL);

	dmem_libgcc_s_hdl = dmem_dlopen(LIBGCC_S_SO);
	backend_unwind_backtrace = dmem_dlsym_impl(dmem_libgcc_s_hdl,
	    "_Unwind_Backtrace");
	backend_unwind_get_ip = dmem_dlsym_impl(dmem_libgcc_s_hdl,
	    "_Unwind_GetIP");
}

/*
 * This enum resembles _Unwid_Reason_Code from unwind.h and are
 * defined to conform with the API interface of the callbacks of
 * _Unwind_Backtrace() [see dmem_bt_cb()}.
 */
typedef enum dmem_bt_codes {
	DBC_CONTINUE = 0,
	DBC_STOP = 4,
	DBC_END_OF_STACK = 5,
} dmem_bt_codes_t;

typedef struct dmem_bt_cb_arg {
	void **bca_stack;
	int bca_limit;
	int bca_count;
} dmem_bt_cb_arg_t;

static int
dmem_bt_cb(void *ctx, void *priv)
{
	dmem_bt_cb_arg_t *bca = priv;

	if (bca->bca_limit == bca->bca_count)
		return DBC_STOP;

	bca->bca_stack[bca->bca_count] = (void *) backend_unwind_get_ip(ctx);
	bca->bca_count++;

	return DBC_CONTINUE;
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
	struct dmem_alloc_entry *dae_next;
	struct dmem_alloc_entry *dae_prev;
	dmem_tx_t dae_tx;
} dmem_alloc_entry_t;

static dmem_alloc_entry_t dmem_alloc_list_head = {
	.dae_next = &dmem_alloc_list_head,
	.dae_prev = &dmem_alloc_list_head,
	.dae_tx = {},
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
dmem_alloc_entry_record_tx(dmem_alloc_entry_t *dae)
{
	dae->dae_tx = (dmem_tx_t) {
		.dt_thread = pthread_self(),
		.dt_stack = {0},
	};
	dmem_bt_cb_arg_t bae = {
		.bca_stack = dae->dae_tx.dt_stack,
		.bca_limit = DMEM_TX_MAX_STACK_DEPTH,
		.bca_count = 0,
	};

	/*
	 * NOTE: We don't do any kind of error-handling
	 * here for now.
	 */
	(void) backend_unwind_backtrace(dmem_bt_cb, &bae);
}


static void
dmem_alloc_entry_add(dmem_alloc_entry_t *dae)
{
	(void) pthread_mutex_lock(&dmem_alloc_list_lock);

	dae->dae_next = dmem_alloc_list_head.dae_next;
	dae->dae_next->dae_prev = dae;
	dae->dae_prev = &dmem_alloc_list_head;
	dmem_alloc_list_head.dae_next = dae;

	dmem_metadata_bytes += sizeof (dmem_alloc_entry_t);

	(void) pthread_mutex_unlock(&dmem_alloc_list_lock);

	dmem_alloc_entry_record_tx(dae);
}

static void
dmem_alloc_entry_remove(dmem_alloc_entry_t *dae)
{

	(void) pthread_mutex_lock(&dmem_alloc_list_lock);

	dae->dae_next->dae_prev = dae->dae_prev;
	dae->dae_prev->dae_next = dae->dae_next;

	dmem_metadata_bytes -= sizeof (dmem_alloc_entry_t);

	(void) pthread_mutex_unlock(&dmem_alloc_list_lock);
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
 * Note the initialization step wouldn't work in a concurrent settings
 * as it currently has no locks to guard its internal structures.
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

	dmem_load_unwind_backtrace();
	dmem_options_parse();

	initialization = false;
}

static void
__attribute__((destructor))
dmem_fini()
{
	if (dmem_libgcc_s_hdl != NULL)
		dlclose(dmem_libgcc_s_hdl);
	if (dmem_abort_on_shutdown)
		abort();
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
	if (dmem_log_allocs) {
		dmem_size = dmem_alloc_entry_full_size(size);
	}

	void *p = backend_malloc(dmem_size);
	if (dmem_log_allocs) {
		dmem_alloc_entry_add(p);
		p = dmem_alloc_entry_get_ptr(p);
	}

	if (dmem_trace_stderr)
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
	if (dmem_log_allocs) {
		/*
		 * The following logic was implemented as a placeholder
		 * until we come up with something better and has the
		 * following problems:
		 *
		 * [1] If we have a lot of small elements the memory
		 *     overhead incured can be severe (e.g. 1000
		 *     4-byte elements, normally around ~4KB, would
		 *     now consume ~120KB - 30x more).
		 *
		 * [2] The memory overhead will also be severe for
		 *     elements that are too big (e.g. allocating
		 *     one 1MB element, would consume 2MBs now).
		 */
		size_t metadata_size = sizeof (dmem_alloc_entry_t);
		if (size < metadata_size) {
			dmem_size += metadata_size;
		} else {
			dmem_nelem += 1;
		}
	}

	void *p = backend_calloc(dmem_nelem, dmem_size);
	if (dmem_log_allocs) {
		dmem_alloc_entry_add(p);
		p = dmem_alloc_entry_get_ptr(p);
	}

	if (dmem_trace_stderr)
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
	if (dmem_log_allocs) {
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
	if (dmem_log_allocs && size > 0) {
		dmem_alloc_entry_add(p);
		p = dmem_alloc_entry_get_ptr(p);
	}

	if (dmem_trace_stderr)
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
	if (dmem_log_allocs) {
		dmem_ptr = dmem_alloc_entry_get_from_ptr(ptr);
		dmem_alloc_entry_remove(dmem_ptr);
	}

	backend_free(dmem_ptr);
	if (dmem_trace_stderr)
		dmem_printf("free(%p)\n", ptr);
}
