/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_AZUREAPIMANAGEMENT_REPOSITORYKEY_H
#define BRIAR_AZUREAPIMANAGEMENT_REPOSITORYKEY_H

#include "briar.h"

/* This provider's three Git commands need different output modes. No shell,
 * HTTP substitution or native process execution is supplied by this seam. */
typedef enum {
    BR_AZUREAPIM_GIT_DISCARD,
    BR_AZUREAPIM_GIT_STDOUT,
    BR_AZUREAPIM_GIT_COMBINED
} br_azureapim_git_output;

typedef struct {
    br_bytes output;
    char *leaf_error;
    bool not_found;
} br_azureapim_git_result;

/* argv has argc entries, starting with "git"; no terminal NULL is required.
 * Return 0 for command success, 1 for command failure, -1 for resource failure.
 * On EVERY return the caller owns output/leaf_error, including partial results.
 * The runner must not invent argv/output error text or discover credentials. */
typedef int (*br_azureapim_git_run_fn)(void *user, const char *const *argv,
                                      size_t argc, br_azureapim_git_output,
                                      br_azureapim_git_result *);

/* Configure only while scanners are quiescent, before workers. The provider
 * copies this function/user pair into its existing opaque state. NULL resets
 * the explicit unsupported native-Git guard; no process is spawned by default. */
void br_azureapimanagement_repositorykey_set_git_runner(br_azureapim_git_run_fn,
                                                       void *user);

#endif
