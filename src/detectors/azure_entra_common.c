/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/azure_entra/common.go and
 * detectors/fp_uuids.txt. Credential exchange policy stays with each provider. */
#include "azure_entra_common.h"
#include "host_cache.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define UUID_PATTERN "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
/* The source's dot-or-whitespace union denotes every rune. Scoped DOTALL avoids
 * that exhaust PCRE2's match limit on otherwise ordinary whitespace padding. */
static const char tenant_pattern[] =
    "(?i)(?:(?:login\\.microsoftonline\\.com/|(?:login|sts)\\.windows\\.net/|(?:t[ae]n[ae]nt(?:[ ._-]?id)?|\\btid)(?s:.){0,60}?)(" UUID_PATTERN ")"
    "|https?://(" UUID_PATTERN ")|X-AnchorMailbox(?s:.){0,60}?@(" UUID_PATTERN ")"
    "|/(" UUID_PATTERN ")/(?:oauth2/v2\\.0|B2C_1\\w+|common|discovery|federationmetadata|kerberos|login|openid/|reprocess|resume|saml2|token|uxlogout|v2\\.0|wsfed))";
static const char client_pattern[] =
    "(?i)(?:(?:app(?:lication)?|client)(?:[ ._-]?id)?|username| -u)(?s:.){0,45}?(" UUID_PATTERN ")";
#undef UUID_PATTERN

static const char *const false_uuids[] = {
    "00000000-0000-0000-0000-000000000000", "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333",
    "44444444-4444-4444-4444-444444444444", "55555555-5555-5555-5555-555555555555",
    "66666666-6666-6666-6666-666666666666", "77777777-7777-7777-7777-777777777777",
    "88888888-8888-8888-8888-888888888888", "99999999-9999-9999-9999-999999999999",
    "12345678-1234-1234-1234-123456789abc", "23456789-2345-2345-2345-23456789abcd",
    "34567890-3456-3456-3456-34567890bcde", "45678901-4567-4567-4567-45678901cdef",
    "56789012-5678-5678-5678-56789012def0", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "cccccccc-cccc-cccc-cccc-cccccccccccc",
    "dddddddd-dddd-dddd-dddd-dddddddddddd", "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
    "ffffffff-ffff-ffff-ffff-ffffffffffff", "deadbeef-dead-beef-dead-beefdeadbeef",
    "cafebabe-cafe-babe-cafe-babecafebabe", "badc0ffee-badc-0ffe-badc-0ffeebadc0f",
    "deadface-dead-face-dead-facedeadface", "feedface-feed-face-feed-facefeedface",
    "a1b2c3d4-a1b2-c3d4-a1b2-c3d4a1b2c3d4", "98765432-9876-5432-9876-543298765432",
    "abcdefab-cdef-abcd-efab-cdefabcdefab", "a0a0a0a0-a0a0-a0a0-a0a0-a0a0a0a0a0a0",
    "b0b0b0b0-b0b0-b0b0-b0b0-b0b0b0b0b0b0", "c0c0c0c0-c0c0-c0c0-c0c0-c0c0c0c0c0c0",
    "d0d0d0d0-d0d0-d0d0-d0d0-d0d0d0d0d0d0", "e0e0e0e0-e0e0-e0e0-e0e0-e0e0e0e0e0e0",
    "f0f0f0f0-f0f0-f0f0-f0f0-f0f0f0f0f0f0", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
};
static br_regex *clients_regex, *tenants_regex, *domains_regex;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

int br_azure_entra_common_init(char **error)
{
    if (error) *error = NULL;
    if (!clients_regex && br_regex_compile(client_pattern, &clients_regex, error)) return -1;
    if (!tenants_regex && br_regex_compile(tenant_pattern, &tenants_regex, error)) return -1;
    if (!domains_regex && br_regex_compile("([\\w-]+\\.onmicrosoft\\.com)", &domains_regex, error)) return -1;
    return 0;
}

typedef struct { br_slice input; br_captures *out; char **error; } id_matches;
static int add_uuid(void *user, const br_span *groups, size_t count)
{
    id_matches *matches = user;
    for (size_t i = 1; i < count; ++i) {
        if (groups[i].begin == SIZE_MAX || groups[i].begin == groups[i].end) continue;
        if (groups[i].end - groups[i].begin != 36) return fail(matches->error, "invalid Azure UUID capture");
        char uuid[37];
        for (size_t at = 0; at < 36; ++at) {
            unsigned char c = matches->input.data[groups[i].begin + at];
            uuid[at] = (char)(c >= 'A' && c <= 'Z' ? c + 'a' - 'A' : c);
        }
        uuid[36] = 0;
        for (size_t at = 0; at < sizeof(false_uuids)/sizeof(false_uuids[0]); ++at)
            if (!strcmp(uuid, false_uuids[at])) return 0;
        br_slice value = {(const unsigned char *)uuid, 36};
        if (br_ascii_shannon_entropy(value) < 3.0) return 0;
        return br_captures_push(matches->out, value, true, matches->error);
    }
    return 0;
}

int br_azure_entra_find_ids(br_slice input, br_captures *clients, br_captures *tenants, char **error)
{
    if (error) *error = NULL;
    if (!clients || !tenants || (!input.data && input.len) || !clients_regex || !tenants_regex || !domains_regex)
        return fail(error, "invalid or uninitialized Azure context matching");
    id_matches client_matches = {input, clients, error}, tenant_matches = {input, tenants, error};
    int rc = br_regex_each(clients_regex, input, add_uuid, &client_matches, error);
    if (!rc) rc = br_regex_each(tenants_regex, input, add_uuid, &tenant_matches, error);
    if (!rc) rc = br_captures_find(domains_regex, input, tenants, true, error);
    return rc;
}

typedef struct tenant_call {
    struct tenant_call *next;
    pthread_cond_t ready;
    size_t refs;
    int status;
    bool done, exists;
    char tenant[];
} tenant_call;
static br_host_cache tenant_cache = BR_HOST_CACHE_INIT;
static pthread_mutex_t tenant_mutex = PTHREAD_MUTEX_INITIALIZER;
static tenant_call *tenant_calls;

static void release_call(tenant_call *call)
{
    if (--call->refs) return;
    pthread_cond_destroy(&call->ready);
    free(call);
}

static int query_tenant(const br_scan_ctx *ctx, int32_t type, const char *tenant, bool *exists)
{
    static const char prefix[] = "https://login.microsoftonline.com/";
    static const char suffix[] = "/.well-known/openid-configuration";
    size_t len = strlen(tenant), overhead = sizeof(prefix) - 1 + sizeof(suffix);
    if (len > SIZE_MAX - overhead) return -1;
    char *url = malloc(len + overhead);
    if (!url) return -1;
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, tenant, len);
    memcpy(url + sizeof(prefix) - 1 + len, suffix, sizeof(suffix));
    const br_http_request request = {.method = "GET", .url = url, .profile = BR_HTTP_SANE, .detector_type = type};
    br_http_response response = {0};
    char *error = NULL;
    int sent = br_http_send(ctx, &request, &response, &error);
    *exists = !sent && response.status == 200;
    br_http_release(ctx, &response);
    free(error); free(url);
    return 0; /* All HTTP failures become cached false; body errors are ignored. */
}

int br_azure_entra_tenant_exists(const br_scan_ctx *ctx, int32_t type, const char *tenant, bool *exists, char **error)
{
    if (error) *error = NULL;
    if (exists) *exists = false;
    if (!tenant || !exists) return fail(error, "invalid Azure tenant query");
    bool found = false;
    if (br_host_cache_get_bool(&tenant_cache, tenant, exists, &found)) return fail(error, "cannot read Azure tenant cache");
    if (found) return 0;
    pthread_mutex_lock(&tenant_mutex);
    /* Close the race with a query that filled the cache before this lock. */
    if (br_host_cache_get_bool(&tenant_cache, tenant, exists, &found)) {
        pthread_mutex_unlock(&tenant_mutex);
        return fail(error, "cannot read Azure tenant cache");
    }
    if (found) { pthread_mutex_unlock(&tenant_mutex); return 0; }
    for (tenant_call *call = tenant_calls; call; call = call->next) {
        if (strcmp(call->tenant, tenant)) continue;
        ++call->refs;
        while (!call->done) pthread_cond_wait(&call->ready, &tenant_mutex);
        int status = call->status;
        *exists = call->exists;
        release_call(call);
        pthread_mutex_unlock(&tenant_mutex);
        return status ? fail(error, "cannot check Azure tenant") : 0;
    }
    size_t len = strlen(tenant);
    if (len > SIZE_MAX - sizeof(tenant_call) - 1) {
        pthread_mutex_unlock(&tenant_mutex);
        return fail(error, "Azure tenant name too large");
    }
    tenant_call *call = calloc(1, sizeof(*call) + len + 1);
    if (!call || pthread_cond_init(&call->ready, NULL)) {
        free(call); pthread_mutex_unlock(&tenant_mutex);
        return fail(error, "cannot allocate Azure tenant query");
    }
    memcpy(call->tenant, tenant, len + 1);
    call->refs = 1;
    call->next = tenant_calls; tenant_calls = call;
    pthread_mutex_unlock(&tenant_mutex);
    bool result = false;
    int status = query_tenant(ctx, type, tenant, &result);
    if (!status) status = br_host_cache_set_bool(&tenant_cache, tenant, result);
    pthread_mutex_lock(&tenant_mutex);
    tenant_call **link = &tenant_calls;
    while (*link != call) link = &(*link)->next;
    *link = call->next;
    call->status = status; call->exists = result; call->done = true;
    pthread_cond_broadcast(&call->ready);
    release_call(call);
    pthread_mutex_unlock(&tenant_mutex);
    *exists = result;
    return status ? fail(error, "cannot check Azure tenant") : 0;
}
