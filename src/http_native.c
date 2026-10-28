/* SPDX-License-Identifier: AGPL-3.0-only */
#include "http_internal.h"
#include "detectors/detectors.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

/* Each entry represents an actual upstream package client, not a rule that
 * detector types define client identity. Duffel's entry is its default client.
 * This runtime does not claim process-global sharing across separate engines. */
static int (*const source_clients[])(const br_detector **, char **) = {
    br_cliengo_init,
    br_clockify_init,
    br_databox_init,
    br_duffeltoken_init,
    br_finage_init,
    br_geocode_init,
    br_gitter_init,
};
#define SOURCE_CLIENT_COUNT (sizeof(source_clients) / sizeof(*source_clients))

struct br_native_http {
    const br_transport *raw;
    struct {
        const br_detector *detector;
        br_http_client *client;
    } sources[SOURCE_CLIENT_COUNT];
};

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return 1;
}

int br_native_http_init(br_native_http **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid native HTTP runtime output");
    *out = NULL;
    br_native_http *runtime = calloc(1, sizeof(*runtime));
    if (!runtime) return fail(error, "out of memory creating native HTTP runtime");
    runtime->raw = br_curl_transport_init(error);
    if (!runtime->raw) goto failed;
    /* Curl's descriptor has null, process-lifetime userdata. This enclosing
     * runtime, rather than an individual client, owns its initialization. */
    br_http_owned_backend backend = {.transport = *runtime->raw};
    for (size_t i = 0; i < SOURCE_CLIENT_COUNT; ++i) {
        if (source_clients[i](&runtime->sources[i].detector, error) ||
            br_http_client_init(&runtime->sources[i].client, backend, BR_HTTP_SANE, error))
            goto failed;
    }
    *out = runtime;
    return 0;
failed:
    br_native_http_destroy(runtime);
    return 1;
}

const br_transport *br_native_http_raw(const br_native_http *runtime)
{
    return runtime ? runtime->raw : NULL;
}

void br_native_http_bind(const br_native_http *runtime, const br_detector *detector,
                         br_scan_ctx *context)
{
    if (!runtime || !context || context->transport != runtime->raw) return;
    for (size_t i = 0; i < SOURCE_CLIENT_COUNT; ++i) {
        if (detector != runtime->sources[i].detector) continue;
        context->transport = br_http_client_transport(runtime->sources[i].client);
        return;
    }
    /* Unknown/custom descriptors keep raw curl, including its keyed guard. */
}

void br_native_http_destroy(br_native_http *runtime)
{
    if (!runtime) return;
    for (size_t i = 0; i < SOURCE_CLIENT_COUNT; ++i) {
        br_http_client *client = runtime->sources[i].client;
        /* As for the owned-client API, backend re-entry violates the external
         * quiescence precondition. Never end curl's lifetime in that case. */
        if (client && br_http_client_drain(client, NULL)) return;
    }
    for (size_t i = 0; i < SOURCE_CLIENT_COUNT; ++i)
        br_http_client_destroy(runtime->sources[i].client);
    if (runtime->raw) curl_global_cleanup();
    free(runtime);
}
