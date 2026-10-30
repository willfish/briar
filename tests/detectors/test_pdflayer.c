/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../support/detector_test.h"
#include "../../src/detectors/findings.h"

int br_pdflayer_init(const br_detector **out, char **error);

#define br_results_push pdflayer_real_push
#define br_result_set_verification_error pdflayer_real_setter
#include "../../src/result.c"
#undef br_results_push
#undef br_result_set_verification_error

static const char key[] = "b7c9d2e5f6a8b3c4d1e0f2a4b6c8d1e3";
static const char other[] = "0123456789abcdef0123456789abcdef";
static const char url[] = "https://api.pdflayer.com/api/convert?access_key=";
static size_t setter_calls, push_calls, push_fail_after;
static bool push_armed;

int br_results_push(br_results *out, br_result *result)
{
    ++push_calls;
    if (push_armed && push_calls == push_fail_after) return 1;
    return pdflayer_real_push(out, result);
}

int br_result_set_verification_error(br_result *result, const char *cause,
                                     const br_slice *secrets, size_t count)
{
    ++setter_calls;
    return pdflayer_real_setter(result, cause, secrets, count);
}

static const br_detector *open_detector(int (*init)(const br_detector **, char **))
{
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(init(NULL, &error) != 0 && error && !strcmp(error, "invalid PdfLayer detector output"));
    free(error);
    CHECK(init(&detector, &error) == 0 && detector && !error);
    CHECK(detector->type == 493 && detector->version == 0 && !strcmp(detector->name, "PdfLayer"));
    CHECK(!strcmp(detector->description, "PdfLayer is a service for converting HTML documents to PDF. PdfLayer API keys can be used to access and utilize the PDF conversion service."));
    CHECK(detector->nkeywords == 1 && !strcmp(detector->keywords[0], "pdflayer"));
    CHECK(detector->max_secret_size == -1 && detector->start_offset == -1 && detector->max_credential_span == -1);
    return detector;
}

static void exercise(const br_detector *detector)
{
    char input[200], expected[sizeof(url) + 32 + 64];
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    snprintf(expected, sizeof(expected),
             "%s%s&document_url=https://pdflayer.com/downloads/invoice.html", url, key);
    snprintf(input, sizeof(input), "pdflayer %s", key);
    br_results out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 1 && !http.calls && !http.releases);
    test_key_result(&out.items[0], 493, key, "key");
    br_results_clear(&out);
    snprintf(input, sizeof(input), "pdflayer %s pdflayer %s", key, other);
    out = test_scan(detector, &ctx, false, input, strlen(input));
    CHECK(out.len == 2);
    br_results_clear(&out);
    const char *rejected[] = {
        "pdflayer B7C9D2E5F6A8B3C4D1E0F2A4B6C8D1E3",
        "pdflayer b7c9d2e5f6a8b3c4d1e0f2a4b6c8d1e3a",
    };
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        br_results none = test_scan(detector, &ctx, false, rejected[i], strlen(rejected[i]));
        CHECK(!none.len && !http.calls && !http.releases);
        br_results_clear(&none);
    }
    /* Status and the Contents marker both gate verification; a read error
     * defeats every byte even when the marker is present. */
    static const char marker[] = "{\"Contents\":\"pdf\"}";
    const struct { int status; const char *body; const char *read_error; bool verified; } cases[] = {
        {200, marker, NULL, true},
        {204, marker, NULL, true},
        {200, "{\"other\":1}", NULL, false},
        {401, marker, NULL, false},
        {500, marker, NULL, false},
        {200, marker, "read failed", false},
    };
    snprintf(input, sizeof(input), "pdflayer %s", key);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        http.calls = http.releases = 0;
        http.send_rc = 0;
        http.send_error = NULL;
        http.response = (br_http_response){.status = cases[i].status,
            .body = {(const unsigned char *)cases[i].body, cases[i].body ? strlen(cases[i].body) : 0},
            .body_error = cases[i].read_error};
        out = test_scan(detector, &ctx, true, input, strlen(input));
        CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
        CHECK(out.items[0].verified == cases[i].verified && !out.items[0].verification_error);
        br_results_clear(&out);
    }
    http.calls = http.releases = 0;
    http.send_rc = 1;
    http.send_error = "timeout";
    out = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(out.len == 1 && http.calls == 1 && http.releases == 1 && !setter_calls);
    CHECK(!out.items[0].verified && !out.items[0].verification_error);
    br_results_clear(&out);
    http.calls = http.releases = 0;
    out = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!out.len && !http.calls && !http.releases && !setter_calls);
    br_results_clear(&out);
    br_results kept = {0};
    br_result prior = {0};
    CHECK(br_finding_key(&prior, 777, "prior", "key") == 0);
    prior.verification_error = strdup("caller-owned");
    CHECK(prior.verification_error && pdflayer_real_push(&kept, &prior) == 0);
    prior = kept.items[0];
    http.response = (br_http_response){.status = 200,
        .body = {(const unsigned char *)marker, strlen(marker)}};
    push_armed = true;
    push_fail_after = push_calls + 1;
    char *error = NULL;
    CHECK(detector->scan(detector, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)},
                         &kept, &error) != 0);
    CHECK(error && !strcmp(error, "cannot append PdfLayer result"));
    free(error);
    CHECK(kept.len == 1 && !memcmp(&kept.items[0], &prior, sizeof(prior)) && http.releases == 1);
    push_armed = false;
    br_results_clear(&kept);
    (void)expected;
}

int main(void)
{
    CHECK(strlen(key) == 32 && strlen(other) == 32);
    exercise(open_detector(br_pdflayer_init));
    CHECK(!setter_calls);
    return test_finish("PdfLayer");
}
