/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_JDBC_PRIVATE_H
#define BRIAR_JDBC_PRIVATE_H

#include "briar.h"

typedef enum { BR_JDBC_MYSQL, BR_JDBC_POSTGRES, BR_JDBC_MSSQL } br_jdbc_driver;
typedef enum {
    BR_JDBC_ERR_NONE, BR_JDBC_ERR_OTHER,
    BR_JDBC_ERR_MYSQL_POINTER, BR_JDBC_ERR_PQ_POINTER
} br_jdbc_error_root;
typedef struct { int32_t number; br_bytes message; } br_jdbc_mssql_value;
typedef struct {
    br_jdbc_error_root root;
    br_bytes outer;
    uint16_t mysql_number;
    br_bytes pq_code;
    br_jdbc_mssql_value *as_mssql_value;
} br_jdbc_error;

/* Own every returned byte buffer/projection on EVERY callback return. Root NONE
 * means ordinary success, even when a diagnostic is empty for another root.
 * as_mssql_value is the FIRST errors.As-compatible VALUE, not pointer containment,
 * an Error.All search, a diagnostic classifier or a verification verdict. */
void br_jdbc_error_clear(br_jdbc_error *);

typedef struct {
    int (*open)(void *user, br_jdbc_driver, br_slice dsn,
                void **db, br_jdbc_error *ordinary, char **fatal);
    int (*ping)(void *user, void *db, const br_scan_ctx *child,
                br_jdbc_error *ordinary, char **fatal);
    int (*close)(void *user, void *db, br_jdbc_error *ordinary, char **fatal);
} br_jdbc_sql_ops;

/* Whole sql.Open / DB.PingContext / DB.Close calls, NOT raw driver methods.
 * Zero means completed with success or ordinary error in the separate record;
 * EVERY nonzero is fatal. Open takes no context and publishes a handle only on
 * success; callbacks clean unpublished partial handles. Close consumes a handle
 * on EVERY return. Close after Ping even on fatal Ping; classify after Close.
 * Ignore ordinary Close errors, preserve first fatal during required cleanup.
 * Borrow request/context only through each call. The caller keeps user alive
 * and ensures thread safety/quiescence. No native DB or ambient discovery is
 * authorized by this private boundary; absent ops remain explicitly unsupported.
 * Legacy PQ/MSSQL connection acquisition inside Ping uses driver background
 * paths, so the child timeout is not a blanket source connection-time bound. */
typedef struct {
    br_regex *regex;
    br_regex *redact;
    const br_jdbc_sql_ops *sql;
    void *sql_user;
} br_jdbc_state;

typedef struct br_jdbc_binding br_jdbc_binding;
/* Clone an initialized, lifetime-valid JDBC descriptor/state. Regex and public
 * descriptor storage remain borrowed from base; copy ops into immutable owned
 * configuration. user remains caller-owned. No globals or HTTP userdata. */
int br_jdbc_binding_init(const br_detector *base, const br_jdbc_sql_ops *, void *user,
                         br_jdbc_binding **out, char **fatal);
const br_detector *br_jdbc_binding_detector(const br_jdbc_binding *);
void br_jdbc_binding_destroy(br_jdbc_binding *);

typedef struct { br_bytes user, password, address, database; } br_jdbc_mysql_dsn;
typedef enum { BR_JDBC_DSN_ACCEPTED, BR_JDBC_DSN_REJECTED } br_jdbc_dsn_status;
/* Parent-owned isolated MPL parser. Project normalized driver fields only;
 * JDBC's password requirement, tcp(...) wrapper and URI fallback are caller
 * policy. Rejection is separate; every nonzero is fatal, including reached
 * panic/unsupported dependencies. Start empty; clear after every outcome. */
int br_jdbc_mysql_parse_dsn(br_slice, br_jdbc_mysql_dsn *, br_jdbc_dsn_status *, char **fatal);
void br_jdbc_mysql_dsn_clear(br_jdbc_mysql_dsn *);

#endif
