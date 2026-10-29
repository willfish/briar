/* SPDX-License-Identifier: AGPL-3.0-only */
#include "jdbc_private.h"
#include <stdlib.h>
#include <string.h>

struct br_jdbc_binding {
    br_detector detector;
    br_jdbc_state state;
    br_jdbc_sql_ops sql;
};

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

void br_jdbc_error_clear(br_jdbc_error *error)
{
    if (!error) return;
    free(error->outer.data); free(error->pq_code.data);
    if (error->as_mssql_value) {
        free(error->as_mssql_value->message.data);
        free(error->as_mssql_value);
    }
    *error = (br_jdbc_error){0};
}

int br_jdbc_binding_init(const br_detector *base, const br_jdbc_sql_ops *sql, void *user,
                         br_jdbc_binding **out, char **error)
{
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (!out || !base || base->type != 10 || base->version != 0 || !base->state ||
        !base->scan || !sql || !sql->open || !sql->ping || !sql->close)
        return fail(error, "invalid JDBC SQL binding arguments");
    br_jdbc_binding *binding = malloc(sizeof(*binding));
    if (!binding) return fail(error, "cannot clone JDBC SQL binding");
    binding->detector = *base;
    binding->state = *(const br_jdbc_state *)base->state;
    binding->sql = *sql;
    binding->state.sql = &binding->sql;
    binding->state.sql_user = user;
    binding->detector.state = &binding->state;
    *out = binding;
    return 0;
}

const br_detector *br_jdbc_binding_detector(const br_jdbc_binding *binding)
{
    return binding ? &binding->detector : NULL;
}

void br_jdbc_binding_destroy(br_jdbc_binding *binding)
{
    free(binding);
}
