/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/http_internal.h"
#include "../../src/detectors/detectors.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned assertions;
#define CHECK(expr) do { ++assertions; if (!(expr)) { \
    fprintf(stderr, "FAIL native HTTP runtime:%d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

static bool never_cancel(void *user) { ++*(unsigned *)user; return false; }

static void unchanged(const br_scan_ctx *actual, const br_scan_ctx *base)
{
    CHECK(actual->deadline_monotonic_ms == base->deadline_monotonic_ms);
    CHECK(actual->cancelled == base->cancelled && actual->cancel_user == base->cancel_user);
    CHECK(actual->user_agent == base->user_agent && actual->endpoints == base->endpoints);
    CHECK(actual->options == base->options);
}

int main(void)
{
    const struct { int (*factory)(const br_detector **, char **); int type; br_http_profile profile; } sources[] = {
        {br_cliengo_init, 710, BR_HTTP_SANE}, {br_clockify_init, 280, BR_HTTP_SANE}, {br_databox_init, 834, BR_HTTP_SANE},
        {br_duffeltoken_init, 1059, BR_HTTP_SANE}, {br_finage_init, 423, BR_HTTP_SANE}, {br_geocode_init, 486, BR_HTTP_SANE},
        {br_gitter_init, 555, BR_HTTP_SANE},
        {br_holidayapi_init, 361, BR_HTTP_SANE},
        {br_ipinfo_init, 939, BR_HTTP_SANE},
        {br_hashicorpvaultbatchtoken_init, 1061, BR_HTTP_DETECTOR_PUBLIC},
        {br_hashicorpvaulttoken_init, 1062, BR_HTTP_DETECTOR_PUBLIC},
        {br_loadmill_init, 758, BR_HTTP_SANE},
    };
    char *error = NULL;
    CHECK(br_native_http_init(NULL, &error) && error);
    free(error); error = NULL;
    CHECK(!br_native_http_raw(NULL));
    br_native_http_bind(NULL, NULL, NULL);
    br_native_http_destroy(NULL);
    br_native_http *runtime = NULL;
    CHECK(!br_native_http_init(&runtime, &error) && runtime && !error);
    const br_transport *raw = br_native_http_raw(runtime);
    CHECK(raw && raw->send && raw->release && !raw->user && !br_http_client_is_owned(raw));
    br_json *options = json_object_new_object(); CHECK(options);
    unsigned cancellations = 0;
    br_scan_ctx base = {.transport = raw, .deadline_monotonic_ms = 12345,
        .cancelled = never_cancel, .cancel_user = &cancellations,
        .user_agent = "native-runtime-unit", .options = options};
    const br_transport *clients[sizeof(sources) / sizeof(*sources)] = {0};
    const br_detector *detector = NULL;
    for (size_t i = 0; i < sizeof(sources) / sizeof(*sources); ++i) {
        CHECK(!sources[i].factory(&detector, &error) && detector && !error);
        CHECK(detector->type == sources[i].type && detector->version == 0);
        br_scan_ctx local = base;
        br_native_http_bind(runtime, detector, &local);
        unchanged(&local, &base);
        CHECK(local.transport != raw && br_http_client_is_owned(local.transport) && local.transport->user);
        CHECK(base.transport == raw); /* A local binding cannot mutate its base. */
        clients[i] = local.transport;
        for (size_t j = 0; j < i; ++j)
            CHECK(clients[j] != clients[i] && clients[j]->user != clients[i]->user);
        br_scan_ctx repeat = base;
        br_native_http_bind(runtime, detector, &repeat);
        CHECK(repeat.transport == clients[i]); /* Across scans/chunks, not per call. */
        br_native_http_bind(runtime, detector, &local);
        CHECK(local.transport == clients[i]); /* Explicit owned client is preserved. */
        br_transport borrowed = *raw;
        local = base; local.transport = &borrowed;
        br_native_http_bind(runtime, detector, &local);
        CHECK(local.transport == &borrowed); unchanged(&local, &base);
        local = base; local.transport = NULL;
        br_native_http_bind(runtime, detector, &local);
        CHECK(!local.transport); unchanged(&local, &base);
        if (sources[i].profile == BR_HTTP_SANE) {
            /* A fresh context reaches this real owned client's SANE preparation,
             * but an invalid UA stops before its shared raw curl backend. */
            br_scan_ctx attempt = {.transport = clients[i], .user_agent = "invalid\r\nagent"};
            unsigned char full_key[64];
            int prefix = snprintf((char *)full_key, sizeof(full_key), "%d:", sources[i].type);
            CHECK(prefix > 0 && (size_t)prefix + 40 <= sizeof(full_key));
            memset(full_key + prefix, 'a', 40);
            size_t key_len = (size_t)prefix + 40;
            if (sources[i].type == 758) CHECK(key_len == 44);
            br_http_request request = {.method = "GET", .url = "http://127.0.0.1:1/",
                .profile = BR_HTTP_SANE, .detector_type = sources[i].type,
                .dedup_key = {full_key, key_len}};
            br_http_response response = {0};
            CHECK(br_http_send(&attempt, &request, &response, &error) != 0 && error &&
                  !strcmp(error, "invalid HTTP user agent"));
            CHECK(!response.status && !response.body.data && !response.body.len && !response.body_error &&
                  !response.headers && !response.nheaders);
            free(error); error = NULL; br_http_release(&attempt, &response);
        }
        if (sources[i].profile == BR_HTTP_DETECTOR_PUBLIC) {
            br_scan_ctx attempt = base;
            attempt.transport = clients[i]; attempt.deadline_monotonic_ms = 0;
            attempt.cancelled = NULL; attempt.cancel_user = NULL; attempt.options = NULL;
            static const unsigned char full_key[] = "native-public:token";
            br_http_request request = {.method = "GET", .url = "http://127.0.0.1:1/",
                .profile = sources[i].profile, .detector_type = sources[i].type,
                .dedup_key = {full_key, sizeof(full_key) - 1}};
            br_http_response response = {0};
            CHECK(br_http_send(&attempt, &request, &response, &error) != 0 && error &&
                  !strcmp(error, "unsupported: native curl HTTP client profile"));
            CHECK(!response.status && !response.body.data && !response.body_error);
            free(error); error = NULL; br_http_release(&attempt, &response);
        }
    }
    /* Matching type, scan and state are not authorization to reuse a source
     * client's namespace. Custom descriptors/clients remain explicit. */
    br_detector clone = *detector;
    br_scan_ctx local = base;
    br_native_http_bind(runtime, &clone, &local);
    CHECK(local.transport == raw); unchanged(&local, &base);
    br_native_http_bind(runtime, NULL, &local);
    CHECK(local.transport == raw);
    const br_detector *other = NULL;
    CHECK(!br_abstract_init(&other, &error) && other && !error);
    br_native_http_bind(runtime, other, &local);
    CHECK(local.transport == raw);
    const unsigned char key[] = "unknown-client:key";
    br_http_request request = {.method = "GET", .url = "http://127.0.0.1:1/",
        .profile = BR_HTTP_SANE, .dedup_key = {key, sizeof(key) - 1}};
    br_http_response response = {0};
    CHECK(br_http_send(&local, &request, &response, &error) && error &&
          !strcmp(error, "unsupported HTTP request coalescing"));
    CHECK(!response.status && !response.body.data && !response.body_error && !cancellations);
    free(error); error = NULL;
    br_http_release(&local, &response);
    json_object_put(options);
    br_native_http_destroy(runtime);
    /* A balanced lifetime can be initialized again, with no source state reset
     * and no claim that two runtimes share Go's process-global package clients. */
    runtime = NULL;
    CHECK(!br_native_http_init(&runtime, &error) && runtime && !error);
    br_native_http_destroy(runtime);
    printf("Native HTTP source-client identity/context/lifecycle: %u assertions, 0 failures; no network sends\n", assertions);
    return 0;
}
