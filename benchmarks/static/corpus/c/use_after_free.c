// SPDX-License-Identifier: Apache-2.0
// Static use-after-free (BHF-437 / CWE-416) and double-free (BHF-438 / CWE-415),
// intraprocedural — the offline analog of the ASan-reported BHF-202/BHF-204, for
// when you cannot fuzz. The safe idioms (NULL-out, reassign, guarded free) must
// stay clean.
#include <stdlib.h>

struct node {
    struct node *next;
};

void uaf_index(char *p) {
    free(p);
    p[0] = 'x';                 // EXPECT BHF-437
}

void uaf_member(struct node *n) {
    free(n);
    n->next = 0;                // EXPECT BHF-437
}

void double_free(char *p) {
    free(p);
    free(p);                    // EXPECT BHF-438
}

void safe_null_out(char *p) {
    free(p);
    p = NULL;
    if (p) {
        p[0] = 'y';             // reassigned to NULL: not a use-after-free
    }
}

void safe_reassign(char *p) {
    free(p);
    p = malloc(8);
    p[0] = 'z';                 // reassigned to a fresh block: no finding
}

void safe_guarded_free(char *p, int c) {
    if (c) {
        free(p);
        return;
    }
    p[0] = 'w';                 // freed only on the returning branch: no finding
}

void safe_two_pointers(char *a, char *b) {
    free(a);
    b[0] = 'q';                 // a distinct pointer: no finding
}

void safe_else_branch(char *p, int c) {
    if (c) {
        free(p);
        return;
    } else {
        p[0] = 'e';             // else path: p was freed only in the if branch
    }
}

void safe_else_if(char *p, int which) {
    if (which == 1) {
        free(p);
    } else if (which == 2) {
        free(p);                // mutually-exclusive branch: not a double free
    }
}

void safe_free_array_elements(char **files, int n) {
    for (int i = 0; i < n; i++) {
        free(files[i]);         // freeing each element ...
    }
    free(files);                // ... then the array itself: not a double free
}

void safe_single_line_guard(char *p, int err) {
    if (err) { free(p); return; }
    free(p);                    // guarded free returned: this is the only free
}

struct alloc { void (*free)(struct alloc *, void *); };

void safe_custom_allocator(struct alloc *mem, void *buf) {
    mem->free(mem, buf);        // member free: `mem` is the handle, not freed
    if (mem->free != 0) {
        mem->free(mem, buf);    // still using the handle: no use-after-free
    }
}
