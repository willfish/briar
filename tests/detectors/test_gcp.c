/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/detectors.h"
#include "../../src/detectors/gcp_oauth.h"
#include "../support/detector_test.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <time.h>

#define TEXT(s) ((br_slice){(const unsigned char *)(s), sizeof(s) - 1})
static char *document(const char *type, const char *key, const char *email, const char *uri)
{
    br_json *o = json_object_new_object(); CHECK(o);
    const char *names[] = {"type", "private_key", "client_email", "token_uri", "private_key_id", "auth_provider_x509_cert_url", "client_x509_cert_url", "project_id"};
    const char *values[] = {type, key, email, uri, "original-kid", "unused", "https://fixture.invalid/certs", "<offline>&"};
    for (size_t i = 0; i < 8; ++i) { br_json *v = json_object_new_string(values[i]); CHECK(v && !json_object_object_add(o, names[i], v)); }
    char *out = strdup(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN)); CHECK(out); json_object_put(o); return out;
}
static br_bytes decode_segment(br_slice raw)
{
    size_t padded = (raw.len + 3) / 4 * 4; unsigned char *text = malloc(padded + 1), *out = malloc(padded + 1); CHECK(text && out);
    for (size_t i = 0; i < raw.len; ++i) text[i] = raw.data[i] == '-' ? '+' : raw.data[i] == '_' ? '/' : raw.data[i];
    for (size_t i = raw.len; i < padded; ++i) text[i] = '=';
    int n = EVP_DecodeBlock(out, text, (int)padded); CHECK(n >= 0 && (size_t)n >= padded - raw.len);
    free(text); return (br_bytes){out, (size_t)n - (padded - raw.len)};
}
typedef struct {
    EVP_PKEY *key; const char *reply, *cause; size_t at, sends, releases, reads;
    int status, send_rc, read_rc; br_slice borrowed; br_bytes copy;
} script;
static int send_bytes(void *user, const br_scan_ctx *ctx, const br_gcp_oauth_request *r,
                        br_gcp_oauth_response *response, br_gcp_oauth_error *error)
{
    script *s = user; ++s->sends; s->at = 0;
    CHECK(ctx && r->role == BR_GCP_JWT_POST && !strcmp(r->method, "POST") && !r->timeout_ns);
    CHECK(r->url.len == sizeof("https://oauth2.googleapis.com/token") - 1 && !memcmp(r->url.data, "https://oauth2.googleapis.com/token", r->url.len));
    CHECK(r->nheaders == 1 && !strcmp(r->headers[0].name, "Content-Type"));
    CHECK(r->headers[0].value.len == sizeof("application/x-www-form-urlencoded") - 1 && !memcmp(r->headers[0].value.data, "application/x-www-form-urlencoded", r->headers[0].value.len));
    CHECK(r->body.len > 10 && !memcmp(r->body.data, "assertion=", 10));
    size_t end = br_slice_find(r->body, TEXT("&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"), 10); CHECK(end != SIZE_MAX);
    br_slice jwt = {r->body.data + 10, end - 10}; size_t a = br_slice_find(jwt, TEXT("."), 0), b = br_slice_find(jwt, TEXT("."), a + 1); CHECK(a != SIZE_MAX && b != SIZE_MAX);
    br_bytes header = decode_segment((br_slice){jwt.data, a}), claims = decode_segment((br_slice){jwt.data + a + 1, b - a - 1}), sig = decode_segment((br_slice){jwt.data + b + 1, jwt.len - b - 1});
    static const char expected_header[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"original-kid\"}";
    CHECK(header.len == sizeof(expected_header) - 1 && !memcmp(header.data, expected_header, header.len));
    br_json *j = json_tokener_parse((const char *)(claims.data[claims.len] = 0, claims.data)); CHECK(j); br_json *v = NULL;
    CHECK(json_object_object_get_ex(j, "iss", &v) && !strcmp(json_object_get_string(v), "briar87@offline.invalid"));
    CHECK(json_object_object_get_ex(j, "scope", &v) && !strcmp(json_object_get_string(v), "https://www.googleapis.com/auth/cloud-platform"));
    CHECK(json_object_object_get_ex(j, "aud", &v) && !strcmp(json_object_get_string(v), "https://oauth2.googleapis.com/token"));
    CHECK(json_object_object_get_ex(j, "iat", &v)); int64_t iat = json_object_get_int64(v);
    CHECK(json_object_object_get_ex(j, "exp", &v) && json_object_get_int64(v) - iat == 3600);
    int64_t now = (int64_t)time(NULL); CHECK(iat >= now - 12 && iat <= now - 8); json_object_put(j);
    EVP_MD_CTX *md = EVP_MD_CTX_new(); EVP_PKEY_CTX *pk = NULL; CHECK(md);
    CHECK(EVP_DigestVerifyInit(md, &pk, EVP_sha256(), NULL, s->key) == 1 && EVP_PKEY_CTX_set_rsa_padding(pk, RSA_PKCS1_PADDING) > 0);
    CHECK(EVP_DigestVerify(md, sig.data, sig.len, jwt.data, b) == 1); EVP_MD_CTX_free(md);
    free(header.data); free(claims.data); free(sig.data);
    s->borrowed = r->body; s->copy.data = malloc(r->body.len); CHECK(s->copy.data); memcpy(s->copy.data, r->body.data, r->body.len); s->copy.len = r->body.len;
    response->status = s->status; response->status_text = TEXT("500 Custom"); response->reader = s;
    if (s->send_rc) { error->text.data = (unsigned char *)strdup(s->cause); CHECK(error->text.data); error->text.len = strlen(s->cause); }
    return s->send_rc;
}
static int read_bytes(void *user, br_gcp_oauth_response *response, unsigned char *out, size_t capacity, size_t *n, br_gcp_oauth_error *error)
{
    script *s = user; CHECK(response->reader == s); ++s->reads;
    size_t remaining = strlen(s->reply) - s->at; *n = remaining < capacity ? remaining : capacity;
    memcpy(out, s->reply + s->at, *n); s->at += *n;
    if (s->read_rc) { error->text.data = (unsigned char *)strdup(s->cause); CHECK(error->text.data); error->text.len = strlen(s->cause); }
    return s->read_rc;
}
static void release_bytes(void *user, br_gcp_oauth_response *response)
{
    script *s = user; CHECK(response->reader == s && s->borrowed.len == s->copy.len && !memcmp(s->borrowed.data, s->copy.data, s->copy.len));
    ++s->releases; free(s->copy.data); s->copy = (br_bytes){0};
}
static void cert_request(test_http *http, const br_scan_ctx *ctx, const br_http_request *r)
{
    (void)http; CHECK(ctx && r->profile == BR_HTTP_DETECTOR_PUBLIC && r->detector_type == 6 && !strcmp(r->method, "GET"));
    CHECK(!strcmp(r->url, "https://fixture.invalid/certs") && r->nheaders == 2 && !strcmp(r->headers[0].name, "Accept") && !strcmp(r->headers[0].value, "application/json"));
    CHECK(!strcmp(r->headers[1].name, "User-Agent") && !strcmp(r->headers[1].value, "TruffleHog"));
}
int main(void)
{
    const br_detector *d = NULL; char *error = NULL; CHECK(br_gcp_init(&d, &error) == 0 && d && !error);
    CHECK(d->type == 6 && !d->version && d->custom_name && !*d->custom_name && d->max_secret_size == 2048 && d->start_offset == 4096);
    char *reason = NULL; CHECK(d->false_positive && !d->false_positive(d, NULL, &reason) && !reason);
    char *input = document("service_account", "not-a-key", "<mailto:briar87@offline.invalid|label>", "<https://oauth2.googleapis.com/token>");
    br_results results = test_scan(d, NULL, false, input, strlen(input)); CHECK(results.len == 1);
    CHECK(results.items[0].raw.len == strlen("briar87@offline.invalid") && !strcmp(results.items[0].redacted, "briar87@offline.invalid"));
    CHECK(strstr((const char *)results.items[0].raw_v2.data, "\\u003coffline\\u003e\\u0026"));
    br_json *part = NULL; CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part) && (size_t)json_object_get_string_len(part) == results.items[0].raw_v2.len);
    br_results_clear(&results);
    size_t len = strlen(input); char *twice = malloc(len * 2 + 2); CHECK(twice); memcpy(twice, input, len); twice[len] = '\n'; memcpy(twice + len + 1, input, len + 1);
    results = test_scan(d, NULL, false, twice, len * 2 + 1); CHECK(results.len == 1); br_results_clear(&results); free(twice); free(input);
    const char *bad = "{\"type\":7,\"type\":\"service_account\",\"auth_provider_x509_cert_url\":\"unused\"}";
    results = test_scan(d, NULL, false, bad, strlen(bad)); CHECK(!results.len); br_results_clear(&results);
    input = document("", "", "image-pulling@authenticated-image-pulling.iam.gserviceaccount.com", ""); results = test_scan(d, NULL, false, input, strlen(input)); CHECK(!results.len); br_results_clear(&results); free(input);
    input = document("invalid_grant", "", "briar87@offline.invalid", ""); results = test_scan(d, NULL, true, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified && results.items[0].verification_error && strstr(results.items[0].verification_error, "unknown credential type")); br_results_clear(&results); free(input);
    EVP_PKEY_CTX *generate = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); EVP_PKEY *key = NULL; CHECK(generate);
    CHECK(EVP_PKEY_keygen_init(generate) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(generate, 2048) > 0 && EVP_PKEY_keygen(generate, &key) > 0); EVP_PKEY_CTX_free(generate);
    BIO *bio = BIO_new(BIO_s_mem()); CHECK(bio && PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) == 1);
    char *pem; long pem_len = BIO_get_mem_data(bio, &pem); CHECK(pem_len > 0); char *pem_copy = malloc((size_t)pem_len + 1); CHECK(pem_copy); memcpy(pem_copy, pem, (size_t)pem_len); pem_copy[pem_len] = 0; BIO_free(bio);
    input = document("service_account", pem_copy, "briar87@offline.invalid", ""); free(pem_copy);
    const br_gcp_oauth_io io = {send_bytes, read_bytes, release_bytes}; br_gcp_state state = *(const br_gcp_state *)d->state; br_detector clone = *d; clone.state = &state; state.io = &io;
    test_http certs = {.send_rc=1, .send_error="synthetic certificate fetch unavailable", .inspect=cert_request}; br_transport transport = test_transport(&certs); br_scan_ctx ctx = {.transport=&transport};
    script s = {.key=key, .reply="{}", .status=200}; state.user = &s;
    results = test_scan(&clone, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && results.items[0].verified && !results.items[0].verification_error);
    CHECK(s.sends == 1 && s.releases == 1 && certs.calls == 1 && certs.releases == 1); br_results_clear(&results);
    s.status = 500; s.reply = "invalid_grant"; results = test_scan(&clone, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && !results.items[0].verified && !results.items[0].verification_error); br_results_clear(&results);
    s.reply = "error body"; results = test_scan(&clone, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && !results.items[0].verified && strstr(results.items[0].verification_error, "500 Custom\nResponse: error body")); br_results_clear(&results);
    s.read_rc = 1; s.cause = "read failed"; results = test_scan(&clone, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && strstr(results.items[0].verification_error, "oauth2: cannot fetch token: read failed")); br_results_clear(&results);
    s.read_rc = 0; s.send_rc = -1; s.cause = "fatal"; results = (br_results){0}; CHECK(clone.scan(&clone, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) < 0 && error && !results.len); free(error); error = NULL; br_results_clear(&results);
    CHECK(s.sends == s.releases && certs.calls == certs.releases);
    CHECK(clone.scan(&clone, NULL, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) < 0 && error && strstr(error, "nil-context")); free(error); error = NULL;
    /* Certificate lookup changes metadata only, never serialized/JWT KID. */
    X509 *certificate = X509_new(); CHECK(certificate && X509_set_version(certificate, 2) == 1 && ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(certificate), -60) && X509_gmtime_adj(X509_getm_notAfter(certificate), 3600));
    CHECK(X509_set_pubkey(certificate, key) == 1); X509_NAME *name = X509_get_subject_name(certificate); CHECK(name);
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"offline.invalid", -1, -1, 0) == 1 && X509_set_issuer_name(certificate, name) == 1 && X509_sign(certificate, key, EVP_sha256()) > 0);
    bio = BIO_new(BIO_s_mem()); CHECK(bio && PEM_write_bio_X509(bio, certificate) == 1);
    pem_len = BIO_get_mem_data(bio, &pem); CHECK(pem_len > 0 && pem_len <= INT_MAX);
    br_json *cert_map = json_object_new_object(), *pem_value = json_object_new_string_len(pem, (int)pem_len); CHECK(cert_map && pem_value && !json_object_object_add(cert_map, "matched-kid", pem_value));
    BIO_free(bio); X509_free(certificate);
    const char *cert_json = json_object_to_json_string_ext(cert_map, JSON_C_TO_STRING_PLAIN); CHECK(cert_json);
    certs.send_rc = 0; certs.send_error = NULL; certs.response.status = 200; certs.response.body = (br_slice){(const unsigned char *)cert_json, strlen(cert_json)};
    s.status = 200; s.reply = "{}"; s.send_rc = s.read_rc = 0;
    results = test_scan(&clone, &ctx, true, input, strlen(input)); CHECK(results.len == 1 && results.items[0].verified);
    CHECK(json_object_object_get_ex(results.items[0].extra_data, "private_key_id", &part) && !strcmp(json_object_get_string(part), "matched-kid"));
    CHECK(strstr((const char *)results.items[0].raw_v2.data, "original-kid") && !strstr((const char *)results.items[0].raw_v2.data, "matched-kid")); br_results_clear(&results);
    /* A later explicit constructor boundary rolls back this invocation only. */
    char *first = document("invalid_grant", "", "keep@offline.invalid", "");
    results = test_scan(d, NULL, false, first, strlen(first)); CHECK(results.len == 1); unsigned char *prior_raw = results.items[0].raw.data;
    br_json *bad_uri = json_tokener_parse(input); CHECK(bad_uri && !json_object_object_add(bad_uri, "token_uri", json_object_new_string("https://fixture.invalid/token")));
    const char *bad_json = json_object_to_json_string_ext(bad_uri, JSON_C_TO_STRING_PLAIN); CHECK(bad_json);
    size_t both_len = strlen(first) + strlen(bad_json) + 1; char *both = malloc(both_len + 1); CHECK(both); snprintf(both, both_len + 1, "%s\n%s", first, bad_json);
    CHECK(clone.scan(&clone, &ctx, true, (br_slice){(const unsigned char *)both, both_len}, &results, &error) < 0 && error && strstr(error, "noncanonical SDK token URI"));
    CHECK(results.len == 1 && results.items[0].raw.data == prior_raw && !strcmp(results.items[0].redacted, "keep@offline.invalid")); free(error); error = NULL;
    br_results_clear(&results); free(first); free(both); json_object_put(bad_uri);
    certs.response.body = TEXT("{\"kid\":\"no PEM\"}");
    CHECK(clone.scan(&clone, &ctx, true, (br_slice){(const unsigned char *)input, strlen(input)}, &results, &error) < 0 && error && strstr(error, "nil certificate"));
    CHECK(!results.len && certs.calls == certs.releases && s.sends == s.releases); free(error); br_results_clear(&results);
    json_object_put(cert_map); free(input); EVP_PKEY_free(key);
    printf("GCP selected extraction and RSA JWT byte flow: %zu assertions, 0 failures; generated disposable RSA key, memory-only transport\n", test_assertions);
    return 0;
}
