/* SPDX-License-Identifier: AGPL-3.0-only */
#include "ldap_private.h"
#include <stdlib.h>
#include <string.h>

struct br_ldap_binding {
    br_detector detector;
    br_ldap_state state;
    br_ldap_io io;
};

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

void br_ldap_error_clear(br_ldap_error *error)
{
    if (!error) return;
    free(error->innermost.data);
    *error = (br_ldap_error){0};
}

int br_ldap_binding_init(const br_detector *base, const br_ldap_io *io, void *user,
                         br_ldap_binding **out, char **fatal)
{
    if (fatal) *fatal = NULL;
    if (out) *out = NULL;
    if (!out || !base || base->type != 901 || base->version != 0 || !base->state ||
        !base->scan || !io || !io->dial || !io->bind || !io->starttls || !io->close)
        return fail(fatal, "invalid LDAP I/O binding arguments");
    br_ldap_binding *binding = malloc(sizeof(*binding));
    if (!binding) return fail(fatal, "cannot clone LDAP I/O binding");
    binding->detector = *base;
    binding->state = *(const br_ldap_state *)base->state;
    binding->io = *io;
    binding->state.io = &binding->io;
    binding->state.io_user = user;
    binding->detector.state = &binding->state;
    *out = binding;
    return 0;
}

const br_detector *br_ldap_binding_detector(const br_ldap_binding *binding)
{
    return binding ? &binding->detector : NULL;
}

void br_ldap_binding_destroy(br_ldap_binding *binding)
{
    free(binding);
}
