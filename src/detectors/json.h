/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_DETECTOR_JSON_H
#define BRIAR_DETECTOR_JSON_H

#include "briar.h"

/* Decode one document, ignoring trailing data. Own *out and *cause. Returns
 * 0 on success (including JSON null), 1 for a decode cause, -1 on allocation failure. */
int br_json_first_document(br_slice body, const char *read_error, br_json **out,
                            size_t *end, char **cause);
/* Decode a whole body: reject trailing non-whitespace instead of ignoring it.
 * Ownership and return codes match br_json_first_document. */
int br_json_document(br_slice body, br_json **out, char **cause);
/* Check original number tokens in a syntax-validated document for Go's
 * float64 map conversion, including overwritten and nested entries. Finite
 * underflow is allowed. Returns 0, 1 with owned cause, or -1 on resource failure. */
int br_json_check_float64_numbers(br_slice document, char **cause);

/* Visit a validated object in source order, including duplicate members.
 * Name, value and its original JSON bytes are borrowed for the callback. Retain
 * values with json_object_get. Use the bytes for typed numeric conversion (native
 * values have json-c's range limits) and nested visits that preserve source order.
 * Return the callback's nonzero result, or -1 on allocation/internal failure. */
typedef int (*br_json_member_fn)(void *, br_slice name, br_json *value, br_slice encoded_value);
int br_json_each_member(br_slice object, br_json_member_fn, void *user);
/* Visit a validated array in source order, including null elements. Borrowing
 * and callback-return semantics match member visits; indices start at zero. */
typedef int (*br_json_element_fn)(void *, size_t index, br_json *value, br_slice encoded_value);
int br_json_each_element(br_slice array, br_json_element_fn, void *user);

/* Borrow string bytes; JSON null is the empty string. Caller checks other types. */
br_slice br_json_text(br_json *);
/* Current ASCII field names, case-folded like Go, including long-s/Kelvin. */
bool br_json_field_name(br_slice name, const char *expected_lowercase);
/* Allocate a Go-style type cause. field=NULL describes a top-level value;
 * otherwise pass the struct-qualified field name and its expected type. */
int br_json_type_cause(br_json *, const char *field, const char *expected, char **cause);

#endif
