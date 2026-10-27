/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/discordbottoken/discordbottoken.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *id; } discordbottoken_patterns;

static int discordbottoken_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void discordbottoken_verify(const br_scan_ctx *ctx, br_slice key, br_slice id,
                                    br_result *result, bool *keep)
{
    /* Source concatenates the provided ID, not @me or an ID derived from the
     * token. Fixed 17-digit captures make a complete 50-byte URL + NUL. Literal
     * bounded concatenation has no heap copy or printf length/error domain. */
    static const char prefix[] = "https://discord.com/api/v8/users/";
    char url[sizeof(prefix) + 17];
    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, id.data, id.len);
    url[sizeof(prefix) - 1 + id.len] = '\0';
    if (!ctx) {
        *keep = false; /* Known constructor failure skips this pair AFTER URL preparation. */
        return;
    }
    /* Headers follow construction. Literal Bot + 59-byte key is 63 bytes +
     * NUL; retain the original regex bytes without Base64/JWT interpretation. */
    char authorization[64];
    memcpy(authorization, "Bot ", 4);
    memcpy(authorization + 4, key.data, key.len);
    authorization[4 + key.len] = '\0';
    const br_header headers[] = {{"Authorization", authorization}};
    const br_http_request request = {
        .method = "GET", .url = url, .headers = headers, .nheaders = 1,
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Source suppresses all Do errors. ABI1 mixes setup/allocation and Do in
     * this domain: suppress it whole, without a setter or text classifier. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Complete stack URL/auth survive send AND release. Source scan-defers
     * Close only and ignores bodies/read errors. Eager buffering/release,
     * full native client, regexp and global engine/output parity stay partial. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int discordbottoken_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                                 br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return discordbottoken_fail(error, "invalid or uninitialized DiscordBotToken scan");
    const discordbottoken_patterns *patterns = detector->state;
    if (!patterns->key || !patterns->id)
        return discordbottoken_fail(error, "uninitialized DiscordBotToken patterns");
    size_t original_len = out->len;
    br_captures keys = {0}, ids = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(patterns->key, input, &keys, false, &owned_error);
    if (rc == 0) rc = br_captures_find(patterns->id, input, &ids, false, &owned_error);
    /* Both ASCII grammars have nonspace edges: TrimSpace is a no-op. Keep all
     * key-major occurrence products, including duplicates, with no local span,
     * token/ID ownership checks, equality filtering, consumption or caching. */
    for (size_t k = 0; rc == 0 && k < keys.len; ++k) {
        br_slice key = br_captures_at(&keys, k);
        for (size_t i = 0; rc == 0 && i < ids.len; ++i) {
            br_slice id = br_captures_at(&ids, i);
            br_result result = {0};
            bool keep = true;
            if (br_finding_pair_bytes(&result, detector->type, key, "key", id, "id", (br_slice){0}) != 0)
                rc = discordbottoken_fail(&owned_error, "cannot create DiscordBotToken result");
            if (rc == 0) {
                /* Redacted is a separate owned ID string, not an alias into
                 * captures/JSON. This resource precedes even constructor skips. */
                result.redacted = malloc(id.len + 1);
                if (!result.redacted) rc = discordbottoken_fail(&owned_error, "cannot allocate DiscordBotToken redaction");
                else { memcpy(result.redacted, id.data, id.len); result.redacted[id.len] = '\0'; }
            }
            if (rc == 0 && verify) discordbottoken_verify(ctx, key, id, &result, &keep);
            if (rc == 0 && keep && br_results_push(out, &result) != 0)
                rc = discordbottoken_fail(&owned_error, "cannot append DiscordBotToken result");
            br_result_clear(&result);
        }
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys);
    br_captures_clear(&ids);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static discordbottoken_patterns discordbottoken_compiled;
static const char *const discordbottoken_keywords[] = {"discord"};
static const br_detector discordbottoken_detector = {
    .type = 65, .version = 0, .name = "DiscordBotToken", .custom_name = "",
    .description = "Discord bot tokens are used to authenticate and control Discord bots. These tokens can be used to interact with the Discord API to perform various bot-related operations.",
    .keywords = discordbottoken_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &discordbottoken_compiled, .scan = discordbottoken_scan,
};

int br_discordbottoken_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return discordbottoken_fail(error, "invalid DiscordBotToken detector output");
    *out = NULL;
    if (!discordbottoken_compiled.key) {
        discordbottoken_patterns compiled = {0};
        if (br_regex_compile_prefixed(discordbottoken_keywords, 1,
                "\\b([A-Za-z0-9_-]{24}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27})\\b", &compiled.key, error) != 0 ||
            br_regex_compile_prefixed(discordbottoken_keywords, 1, "\\b([0-9]{17})\\b", &compiled.id, error) != 0) {
            br_regex_free(compiled.key);
            br_regex_free(compiled.id);
            return -1;
        }
        discordbottoken_compiled = compiled;
    }
    *out = &discordbottoken_detector;
    return 0;
}
