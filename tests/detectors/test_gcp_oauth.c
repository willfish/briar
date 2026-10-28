/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/gcp_oauth.h"
#include "../support/detector_test.h"

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})

typedef struct { size_t remaining, calls; int result; } memory_reader;
static int send_unused(void *user, const br_scan_ctx *ctx, const br_gcp_oauth_request *request,
                        br_gcp_oauth_response *response, br_gcp_oauth_error *error)
{
    (void)user; (void)ctx; (void)request; (void)response; (void)error; CHECK(false); return -1;
}
static int read_memory(void *user, br_gcp_oauth_response *response, unsigned char *out,
                        size_t capacity, size_t *n, br_gcp_oauth_error *error)
{
    (void)response; memory_reader *state = user; ++state->calls;
    *n = state->remaining < capacity ? state->remaining : capacity;
    memset(out, 'A', *n); state->remaining -= *n;
    if (!state->remaining && state->result) {
        static const char cause[] = "reader stopped after partial bytes";
        error->text.data = (unsigned char *)strdup(cause); CHECK(error->text.data);
        error->text.len = sizeof(cause) - 1;
        return state->result;
    }
    return 0;
}
static void release_unused(void *user, br_gcp_oauth_response *response)
{ (void)user; (void)response; }

int main(void)
{
    /* Go QueryEscape byte goldens, fixed source order, no Basic or scope added. */
    const br_gcp_oauth_pair fields[] = {
        {"client_id", TEXT("full.id.apps.googleusercontent.com")},
        {"client_secret", TEXT("x y+~\0\xc3\xa9")},
        {"grant_type", TEXT("refresh_token")}, {"refresh_token", TEXT("a/b=c&d")},
    };
    br_bytes out = {0}; char *fatal = NULL;
    CHECK(br_gcp_oauth_form(fields, 4, &out, &fatal) == 0 && !fatal);
    static const char expected[] = "client_id=full.id.apps.googleusercontent.com&client_secret=x+y%2B~%00%C3%A9&grant_type=refresh_token&refresh_token=a%2Fb%3Dc%26d";
    CHECK(out.len == sizeof(expected) - 1 && !memcmp(out.data, expected, sizeof(expected))); free(out.data);
    const br_gcp_oauth_pair jwt[] = {{"assertion", TEXT("a.b-c_d")}, {"grant_type", TEXT("urn:ietf:params:oauth:grant-type:jwt-bearer")}};
    CHECK(br_gcp_oauth_form(jwt, 2, &out, &fatal) == 0 && !fatal);
    static const char jwt_expected[] = "assertion=a.b-c_d&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer";
    CHECK(out.len == sizeof(jwt_expected) - 1 && !memcmp(out.data, jwt_expected, sizeof(jwt_expected))); free(out.data);
    const br_gcp_oauth_io io = {send_unused, read_memory, release_unused};
    br_gcp_oauth_response response = {0}; br_gcp_oauth_error error = {0};
    memory_reader stream = {((size_t)1 << 20) + 17, 0, 0};
    CHECK(br_gcp_oauth_read(&io, &stream, &response, &out, &error, &fatal) == 0 && !fatal);
    CHECK(out.len == ((size_t)1 << 20) && stream.remaining == 17 && !error.text.data);
    CHECK(out.data[0] == 'A' && out.data[out.len - 1] == 'A' && out.data[out.len] == 0); free(out.data);
    for (int rc = -1; rc <= 1; rc += 2) {
        stream = (memory_reader){3, 0, rc};
        CHECK(br_gcp_oauth_read(&io, &stream, &response, &out, &error, &fatal) == rc);
        CHECK(out.len == 3 && !memcmp(out.data, "AAA", 4) && error.text.len);
        CHECK((fatal != NULL) == (rc < 0)); free(fatal); fatal = NULL;
        free(out.data); br_gcp_oauth_error_clear(&error);
    }
    CHECK(br_gcp_oauth_retrieve_error(TEXT("503 Custom"), TEXT("raw\0tail"), TEXT(""), TEXT("ignored-\xc3\xa9"), TEXT(""), &error, &fatal) == 0 && !fatal);
    static const char raw_error[] = "oauth2: cannot fetch token: 503 Custom\nResponse: raw\0tail";
    CHECK(error.text.len == sizeof(raw_error) - 1 && !memcmp(error.text.data, raw_error, sizeof(raw_error)));
    br_gcp_oauth_error_clear(&error);
    CHECK(br_gcp_oauth_retrieve_error(TEXT("unused"), TEXT("unused"), TEXT("invalid_grant"), TEXT("bad\n\0\v"), TEXT("x\\"), &error, &fatal) == 0 && !fatal);
    static const char quoted_error[] = "oauth2: \"invalid_grant\" \"bad\\n\\x00\\v\" \"x\\\\\"";
    CHECK(error.text.len == sizeof(quoted_error) - 1 && !memcmp(error.text.data, quoted_error, sizeof(quoted_error)));
    br_gcp_oauth_error_clear(&error);
    CHECK(br_gcp_oauth_retrieve_error(TEXT(""), TEXT(""), TEXT("diagnostic-\xc3\xa9"), TEXT(""), TEXT(""), &error, &fatal) < 0 && fatal);
    CHECK(strstr(fatal, "non-ASCII quoted diagnostic") && !error.text.data); free(fatal); fatal = NULL;
    size_t measured, written; unsigned char quoted[16] = {0};
    CHECK(br_gcp_oauth_quote(TEXT("\0\v\x7f"), NULL, 0, &measured, &fatal) == 0 && !fatal && measured == 12);
    CHECK(br_gcp_oauth_quote(TEXT("\0\v\x7f"), quoted, measured, &written, &fatal) == 0 && !fatal && written == measured);
    CHECK(!memcmp(quoted, "\"\\x00\\v\\x7f\"", measured));
    printf("Google OAuth byte mechanics: %zu assertions, 0 failures; memory-only readers, no SDK/service calls\n", test_assertions);
    return 0;
}
