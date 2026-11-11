/* SPDX-License-Identifier: AGPL-3.0-only */
/* Synthetic fixtures from TruffleHog PR #5528; never issued credentials. */
#include "../support/detector_test.h"

static const char *const secrets[] = {
    "svl_secret_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe",
    "svl_secret_wk_hijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN24D8Sa",
    "svl_secret_mk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg182p0W",
};
static const char *const types[] = {"public_api", "worker", "managed_worker"};
static const char id[] = "3f1c2a9e-8b7d-4e6f-9a0b-1c2d3e4f5a6b";

static const br_detector *lookup(void)
{
    const br_detector *const *all = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(br_registry(&all, &count, &error) == 0 && !error);
    for (size_t i = 0; i < count; ++i)
        if (all[i]->type == 1078) return all[i];
    return NULL;
}

static void check_result(const br_result *r, size_t kind, bool paired)
{
    CHECK(r->detector_type == 1078 && !r->verified && !r->verification_error);
    CHECK(r->raw.len == strlen(secrets[kind]));
    CHECK(!memcmp(r->raw.data, secrets[kind], r->raw.len));
    CHECK(json_object_object_length(r->secret_parts) == (paired ? 2 : 1));
    CHECK(!strcmp(json_object_get_string(json_object_object_get(r->secret_parts, "client_secret")), secrets[kind]));
    CHECK(!strcmp(json_object_get_string(json_object_object_get(r->extra_data, "key_type")), types[kind]));
    if (paired) {
        char expected[128];
        snprintf(expected, sizeof(expected), "%s:%s", id, secrets[kind]);
        CHECK(r->raw_v2.len == strlen(expected));
        CHECK(!memcmp(r->raw_v2.data, expected, strlen(expected)));
        CHECK(!strcmp(json_object_get_string(json_object_object_get(r->secret_parts, "client_id")), id));
    } else CHECK(!r->raw_v2.len && !r->raw_v2.data);
}

int main(void)
{
    const br_detector *d = lookup();
    CHECK(d != NULL);
    CHECK(!strcmp(br_detector_type_name(1078), "Serval"));
    CHECK(br_detector_is_default(d, NULL));
    br_json *flags = json_tokener_parse("{\"ServalDetectorEnabled\":false}");
    CHECK(!br_detector_is_default(d, flags));
    json_object_put(flags);
    test_http http = {0};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    char input[512];
    for (size_t k = 0; k < 3; ++k) {
        br_results r = test_scan(d, &ctx, false, secrets[k], strlen(secrets[k]));
        CHECK(r.len == 1);
        check_result(&r.items[0], k, false);
        br_results_clear(&r);
        snprintf(input, sizeof(input), "SERVAL_CLIENT_ID=3F1C2A9E-8B7D-4E6F-9A0B-1C2D3E4F5A6B\nsecret='%s'", secrets[k]);
        r = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(r.len == 1);
        check_result(&r.items[0], k, true);
        br_results_clear(&r);
        /* Checksum failure independent of shape matching, for every tag. */
        strcpy(input, secrets[k]);
        input[strlen(input)-1] = input[strlen(input)-1] == '0' ? '1' : '0';
        r = test_scan(d, &ctx, false, input, strlen(input));
        CHECK(r.len == 0);
        br_results_clear(&r);
    }
    const char *bad[] = {
        "svl_secret_wk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe",
        "svl_secret_xk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe",
        "svl_secret_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCU",
        "svl_secret_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUeA",
        "Asvl_secret_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe",
        "_svl_secret_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe",
        "svl_secret_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe_",
        "SVL_SECRET_pk_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg3VqCUe",
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(*bad); ++i) {
        br_results r = test_scan(d, &ctx, false, bad[i], strlen(bad[i]));
        CHECK(r.len == 0);
        br_results_clear(&r);
    }
    snprintf(input, sizeof(input), "unrelated=%s secret=%s", id, secrets[0]);
    br_results r = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(r.len == 1);
    check_result(&r.items[0], 0, false);
    br_results_clear(&r);
    snprintf(input, sizeof(input), "client=%s client=3F1C2A9E-8B7D-4E6F-9A0B-1C2D3E4F5A6B secret=%s secret=%s", id, secrets[0], secrets[0]);
    r = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(r.len == 1);
    check_result(&r.items[0], 0, true);
    br_results_clear(&r);
    /* Distinct candidate UUIDs pair independently; case variants deduplicate. */
    snprintf(input, sizeof(input), "client=%s client=11111111-1111-4111-8111-111111111111 secret=%s", id, secrets[0]);
    r = test_scan(d, &ctx, false, input, strlen(input));
    CHECK(r.len == 2);
    CHECK(r.items[0].raw_v2.len == 100 && r.items[1].raw_v2.len == 100);
    CHECK(memcmp(r.items[0].raw_v2.data, r.items[1].raw_v2.data, 36));
    br_results_clear(&r);
    /* Invalid inputs fail without losing an already-owned caller result. */
    r = test_scan(d, &ctx, false, secrets[0], strlen(secrets[0]));
    char *invalid_error = NULL;
    CHECK(d->scan(d, &ctx, false, (br_slice){NULL, 1}, &r, &invalid_error) != 0);
    CHECK(invalid_error && r.len == 1);
    free(invalid_error);
    check_result(&r.items[0], 0, false);
    br_results_clear(&r);
    /* Unsupported verification must fail explicitly without any transport use. */
    char *error = NULL;
    CHECK(d->scan(d, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &r, &error) != 0);
    CHECK(error && strstr(error, "not implemented") && !strstr(error, secrets[0]));
    CHECK(r.len == 0 && http.calls == 0 && http.releases == 0);
    free(error);
    br_results_clear(&r);
    return test_finish("serval");
}
