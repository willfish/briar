/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_AZURE_ENTRA_JWT_H
#define BRIAR_AZURE_ENTRA_JWT_H

#include "briar.h"

/* Selected unverified MapClaims, not a JWT verifier. Projection, formatting and
 * HTTP policy belong to each provider. Start zeroed; clear after any return. */
typedef struct {
    bool token_present;
    br_json *app, *email, *upn, *unique_name;
} br_azure_entra_jwt_fields;

/* 0: normal consumer state, including nil token and partial claims.
 * 1: source nil-Claims assertion/panic shape, with no error string.
 * -1: argument/resource failure, with an owned diagnostic when possible. */
int br_azure_entra_jwt_read(br_slice, br_azure_entra_jwt_fields *, char **error);
void br_azure_entra_jwt_clear(br_azure_entra_jwt_fields *);

#endif
