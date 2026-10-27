/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/discordwebhook/discordwebhook.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"

#include <stdlib.h>
#include <string.h>

static int discordwebhook_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static void discordwebhook_verify(const br_scan_ctx *ctx, const char *url, br_result *result)
{
    /* Construction's known nil-context skip precedes this call. Borrow the
     * complete owned capture, including its NUL, through send AND release. */
    const br_http_request request = {
        .method = "GET", .url = url, .profile = BR_HTTP_DETECTOR_PUBLIC,
        .detector_type = result->detector_type,
    };
    br_http_response response = {0};
    char *transport_error = NULL;
    /* Suppress the whole shared setup/allocation/Do domain without a setter or
     * text classifier. No SANE fallback: native PUBLIC must remain fail-closed. */
    if (br_http_send(ctx, &request, &response, &transport_error) == 0)
        result->verified = response.status >= 200 && response.status < 300;
    /* Bodies/read errors do not participate. Source scan-defers Close only;
     * ABI1 eagerly buffers/releases. Injected success does not establish native
     * PUBLIC DNS/proxy/redirect policy, full client, regexp or global parity. */
    br_http_release(ctx, &response);
    free(transport_error);
}

static int discordwebhook_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                               br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return discordwebhook_fail(error, "invalid or uninitialized DiscordWebhook scan");
    size_t original_len = out->len;
    br_captures urls = {0};
    char *owned_error = NULL;
    int rc = br_captures_find(detector->state, input, &urls, false, &owned_error);
    for (size_t i = 0; rc == 0 && i < urls.len; ++i) {
        br_result result = {0};
        /* TrimSpace is a no-op. Preserve occurrences and source prefix captures,
         * including duplicates; create finding resources before any skip. */
        if (br_finding_key_bytes(&result, detector->type, br_captures_at(&urls, i), "key") != 0)
            rc = discordwebhook_fail(&owned_error, "cannot create DiscordWebhook result");
        else if (!verify || ctx) {
            if (verify) discordwebhook_verify(ctx, urls.items[i], &result);
            if (br_results_push(out, &result) != 0)
                rc = discordwebhook_fail(&owned_error, "cannot append DiscordWebhook result");
        } /* verify && !ctx: constructor skip, without an artificial append. */
        br_result_clear(&result);
    }
    if (rc != 0)
        while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&urls);
    if (error) *error = owned_error;
    else free(owned_error);
    return rc == 0 ? 0 : -1;
}

static const char *const discordwebhook_keywords[] = {"https://discord.com/api/webhooks/"};
static br_detector discordwebhook_detector = {
    .type = 66, .version = 0, .name = "DiscordWebhook", .custom_name = "",
    .description = "Discord webhooks are used to send messages to a Discord channel. They can be used to automate messages and send data updates.",
    .keywords = discordwebhook_keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = -1,
    .scan = discordwebhook_scan,
};

int br_discordwebhook_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return discordwebhook_fail(error, "invalid DiscordWebhook detector output");
    *out = NULL;
    if (!discordwebhook_detector.state) {
        br_regex *pattern = NULL;
        /* Direct case-sensitive source regexp: no PrefixRegex, boundaries or
         * end anchor. The literal slash needs no escape in PCRE2's C string. */
        if (br_regex_compile("(https://discord\\.com/api/webhooks/[0-9]{18,19}/[0-9a-zA-Z-]{68})",
                             &pattern, error) != 0) return -1;
        discordwebhook_detector.state = pattern;
    }
    *out = &discordwebhook_detector;
    return 0;
}
