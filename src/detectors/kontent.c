/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/kontent/kontent.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *env; } kontent_patterns;

/* Lowercased fp_uuids.txt, copied here. Not the shared false-positive helper. */
static const char *const fp_uuids[] = {
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
    "33333333-3333-3333-3333-333333333333",
    "44444444-4444-4444-4444-444444444444",
    "55555555-5555-5555-5555-555555555555",
    "66666666-6666-6666-6666-666666666666",
    "77777777-7777-7777-7777-777777777777",
    "88888888-8888-8888-8888-888888888888",
    "99999999-9999-9999-9999-999999999999",
    "12345678-1234-1234-1234-123456789abc",
    "23456789-2345-2345-2345-23456789abcd",
    "34567890-3456-3456-3456-34567890bcde",
    "45678901-4567-4567-4567-45678901cdef",
    "56789012-5678-5678-5678-56789012def0",
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    "cccccccc-cccc-cccc-cccc-cccccccccccc",
    "dddddddd-dddd-dddd-dddd-dddddddddddd",
    "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "deadbeef-dead-beef-dead-beefdeadbeef",
    "cafebabe-cafe-babe-cafe-babecafebabe",
    "badc0ffee-badc-0ffe-badc-0ffeebadc0f",
    "deadface-dead-face-dead-facedeadface",
    "feedface-feed-face-feed-facefeedface",
    "a1b2c3d4-a1b2-c3d4-a1b2-c3d4a1b2c3d4",
    "98765432-9876-5432-9876-543298765432",
    "abcdefab-cdef-abcd-efab-cdefabcdefab",
    "a0a0a0a0-a0a0-a0a0-a0a0-a0a0a0a0a0a0",
    "b0b0b0b0-b0b0-b0b0-b0b0-b0b0b0b0b0b0",
    "c0c0c0c0-c0c0-c0c0-c0c0-c0c0c0c0c0c0",
    "d0d0d0d0-d0d0-d0d0-d0d0-d0d0d0d0d0d0",
    "e0e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0",
    "f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0",
    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
};

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static bool listed_env(br_slice env)
{
    for (size_t i = 0; i < sizeof(fp_uuids) / sizeof(fp_uuids[0]); ++i) {
        size_t n = strlen(fp_uuids[i]);
        if (n == env.len && !memcmp(fp_uuids[i], env.data, n)) return true;
    }
    return false;
}

static int own_borrowed(const char *borrowed, char **owned)
{
    *owned = NULL;
    if (!borrowed) return 0;
    *owned = strdup(borrowed);
    return *owned ? 0 : -1;
}

/* Returns 0 when the caller must store the verdict and call the setter.
 * A NUL key records its cause here and sets *apply false. A reached send
 * releases before either of those caller steps. */
static int verify_kontent(const br_scan_ctx *ctx, br_slice env, br_slice key, br_result *result,
                          bool *apply, bool *verified, char **cause)
{
    /* ey + 34 + wildcard + ey + 400 + wildcard + 43. Do not truncate a longer key. */
    static const char prefix[] = "https://manage.kontent.ai/v2/projects/";
    static const char sentence[] = "The specified API key does not provide the permissions required to access the environment";
    *apply = false;
    *verified = false;
    *cause = NULL;
    if (env.len != 36 || key.len > 483) return -1;
    /* A wildcard may be NUL. Go rejects that Authorization value during Do and
     * still publishes. Do not truncate it into a C string or attempt send. */
    if (memchr(key.data, '\0', key.len)) {
        if (br_result_set_verification_error(result,
                "net/http: invalid header field value for \"Authorization\"", NULL, 0))
            return -1;
        return 0;
    }
    char url[sizeof(prefix) + 36];
    char authorization[7 + 483 + 1];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, env.data, env.len);
    url[sizeof(prefix) - 1 + env.len] = '\0';
    memcpy(authorization, "Bearer ", 7);
    memcpy(authorization + 7, key.data, key.len);
    authorization[7 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    /* http.NewRequest, not NewRequestWithContext. A nil scan context still
     * attempts the client call. Keep transport and user agent. */
    br_scan_ctx background = ctx ? *ctx : (br_scan_ctx){0};
    background.deadline_monotonic_ms = 0;
    background.cancelled = NULL;
    background.cancel_user = NULL;
    br_http_response response = {0};
    char *send_error = NULL;
    char *owned_send = NULL, *owned_body = NULL;
    char status_error[48];
    bool have_status = false;
    int rc = 0;
    int send_rc = br_http_send(&background, &request, &response, &send_error);
    if (send_rc != 0) {
        /* A reached NULL diagnostic stays NULL. Do not invent a missing cause. */
        if (own_borrowed(send_error, &owned_send) != 0) rc = -1;
    } else if (response.status == 200) {
        *verified = true;
    } else if (response.status == 403 && response.body_error) {
        /* Read error wins. Do not project the body. */
        if (own_borrowed(response.body_error, &owned_body) != 0) rc = -1;
    } else if (response.status == 403) {
        if (!response.body.data && response.body.len) rc = -1;
        else if (br_slice_find(response.body, (br_slice){(const unsigned char *)sentence, sizeof(sentence) - 1}, 0) != SIZE_MAX)
            *verified = true;
    } else if (response.status != 401) {
        int n = snprintf(status_error, sizeof(status_error), "unexpected status code: %d", response.status);
        if (n < 0 || (size_t)n >= sizeof(status_error)) rc = -1;
        else have_status = true;
    }
    /* Drain and close before the caller stores Verified or calls the setter.
     * Copy failure and projection failure still release exactly once. */
    br_http_release(&background, &response);
    free(send_error);
    if (!rc && have_status && own_borrowed(status_error, cause) != 0) rc = -1;
    if (rc) {
        free(owned_send);
        free(owned_body);
        free(*cause);
        *cause = NULL;
        *verified = false;
        return -1;
    }
    *apply = true;
    if (!*cause) *cause = owned_send ? owned_send : owned_body;
    else {
        free(owned_send);
        free(owned_body);
    }
    return 0;
}

static int scan_kontent(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                        br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return fail(error, "invalid or uninitialized Kontent scan");
    const kontent_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->env) return fail(error, "uninitialized Kontent patterns");
    br_captures keys = {0}, envs = {0};
    char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->key, input, &keys, true, &owned_error);
    if (!rc) rc = br_captures_find(compiled->env, input, &envs, true, &owned_error);
    /* First-seen unique strings. Env outer, key inner. Both sides are required.
     * Drop listed or low-entropy envs before the product. Do not filter keys. */
    for (size_t e = 0; !rc && e < envs.len; ++e) {
        br_slice env = br_captures_at(&envs, e);
        if (listed_env(env) || br_ascii_shannon_entropy(env) < 3) continue;
        for (size_t k = 0; !rc && k < keys.len; ++k) {
            br_result result = {0};
            br_slice key = br_captures_at(&keys, k);
            if (br_finding_pair_bytes(&result, detector->type, env, "env_id", key, "key", (br_slice){0}))
                rc = fail(&owned_error, "cannot create Kontent result");
            bool apply = false, verified = false;
            char *cause = NULL;
            if (!rc && verify && verify_kontent(ctx, env, key, &result, &apply, &verified, &cause))
                rc = fail(&owned_error, "cannot verify Kontent candidate");
            /* Caller stores the verdict, then the mandatory zero-secret setter.
             * NULL is a checked no-op. Setter +1 is fatal. The owned copy is freed
             * on that path too. */
            if (!rc && apply) {
                result.verified = verified;
                if (br_result_set_verification_error(&result, cause, NULL, 0))
                    rc = fail(&owned_error, "cannot verify Kontent candidate");
            }
            free(cause);
            if (!rc && br_results_push(out, &result))
                rc = fail(&owned_error, "cannot append Kontent result");
            br_result_clear(&result);
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&envs);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc ? -1 : 0;
}

static kontent_patterns patterns;
static const char *const keywords[] = {"kontent"};
static const char *const env_keywords[] = {"kontent", "env"};
static br_detector kontent_detector = {
    .type = 328, .version = 0, .name = "Kontent", .custom_name = "",
    .description = "Kontent is a headless CMS (Content Management System) that allows users to manage and deliver content to any device or application. Kontent API keys can be used to access and manage this content.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .state = &patterns, .scan = scan_kontent,
};

int br_kontent_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid Kontent detector output");
    *out = NULL;
    /* Both dots are wildcard runes. Do not escape them into literal periods. */
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1,
            "\\b(ey[0-9a-zA-Z]{30,34}.ey[0-9a-zA-Z-\\/_]{200,400}.[0-9a-zA-Z-\\/_]{40,43})\\b",
            &patterns.key, error))
        return -1;
    if (!patterns.env && br_regex_compile_prefixed(env_keywords, 2,
            "\\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\b",
            &patterns.env, error)) {
        br_regex_free(patterns.key);
        patterns.key = NULL;
        return -1;
    }
    *out = &kontent_detector;
    return 0;
}
