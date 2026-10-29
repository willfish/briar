/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/jiratoken_url.h"
#include "../support/detector_test.h"

#define SLICE(s) (br_slice){(const unsigned char *)(s), sizeof(s) - 1}

static void endpoint(br_slice input, br_slice expected)
{
    br_bytes host = {0}; char *error = NULL;
    CHECK(br_jiratoken_endpoint_host(input, &host, &error) == 0 && !error);
    CHECK(host.len == expected.len && !memcmp(host.data, expected.data, expected.len));
    CHECK(host.data[host.len] == 0);
    free(host.data);
}

static void request(const char *host, const char *expected, const char *cause, bool no_host)
{
    br_jiratoken_target target = {0}; char *error = NULL;
    CHECK(br_jiratoken_target_init((br_slice){(const unsigned char *)host, strlen(host)}, true, &target, &error) == 0 && !error);
    CHECK(target.original.len == strlen("https://") + strlen(host) + strlen("/gateway/api/graphql"));
    CHECK(!memcmp(target.original.data, "https://", 8));
    CHECK(!memcmp(target.original.data + 8, host, strlen(host)));
    CHECK(!strcmp((const char *)target.original.data + 8 + strlen(host), "/gateway/api/graphql"));
    CHECK(target.original.data[target.original.len] == 0);
    CHECK(cause ? target.cause && !strcmp(target.cause, cause) && !target.url : !target.cause && target.url && !strcmp(target.url, expected));
    CHECK(target.error_url_has_no_host == no_host);
    if (target.url) CHECK(target.url == (const char *)target.original.data || target.url == (const char *)target.projected.data);
    br_jiratoken_target_clear(&target); br_jiratoken_target_clear(&target);
    CHECK(!target.original.data && !target.projected.data && !target.url && !target.cause && !target.error_url_has_no_host);
}

int main(void)
{
    endpoint(SLICE(" \tHTTPS://Acme.atlassian.net:0443/a%2fb?x=1#frag/ \n"), SLICE("Acme.atlassian.net:0443"));
    endpoint(SLICE("acme.atlassian.net///"), SLICE("acme.atlassian.net//"));
    endpoint(SLICE("https://acme.atlassian.net/a%GG"), SLICE("https://acme.atlassian.net/a%GG"));
    endpoint(SLICE("https://acme.atlassian.net/#bad%GG"), SLICE("https://acme.atlassian.net/#bad%GG"));
    endpoint(SLICE("https://acme.atlassian.net/#\0tail"), SLICE("acme.atlassian.net"));
    endpoint(SLICE("raw\0host"), SLICE("raw\0host"));
    endpoint(SLICE("https://a:b:443/x"), SLICE("a:b:443"));
    endpoint(SLICE("https://host:999999999999999999999999999/x"), SLICE("host:999999999999999999999999999"));
    endpoint(SLICE("https://host:/x"), SLICE("host:"));
    endpoint(SLICE("https://[::ffff:192.0.2.1]:443/x"), SLICE("[::ffff:192.0.2.1]:443"));
    endpoint(SLICE("https://[fe80::1%25eth0]/x"), SLICE("[fe80::1%eth0]"));
    endpoint(SLICE("https://[::1%25zone%20name]/x"), SLICE("[::1%zone name]"));
    endpoint(SLICE("https://[127.0.0.1]/x"), SLICE("https://[127.0.0.1]/x"));
    endpoint(SLICE("https://%41.example/x"), SLICE("https://%41.example/x"));
    endpoint(SLICE("https://%C3%A9.example/x"), SLICE("\xc3\xa9.example"));
    endpoint(SLICE("\xc2\xa0https://acme.atlassian.net/\xe3\x80\x80"), SLICE("acme.atlassian.net"));
    endpoint(SLICE(" \r\n"), SLICE(""));
    endpoint(SLICE("opaque:%GG"), SLICE("opaque:%GG"));
    endpoint(SLICE("https://[::bad::]/x"), SLICE("https://[::bad::]/x"));

    request("Acme.atlassian.net", "https://Acme.atlassian.net/gateway/api/graphql", NULL, false);
    request("host:", "https://host/gateway/api/graphql", NULL, false);
    request("a:b:443", "https://a:b:443/gateway/api/graphql", NULL, false);
    request("[::ffff:192.0.2.1]", "https://[::ffff:192.0.2.1]/gateway/api/graphql", NULL, false);
    request("[fe80::1%25eth0]", "https://[fe80::1%25eth0]/gateway/api/graphql", NULL, false);
    request("\xc3\xa9.example", "https://%C3%A9.example/gateway/api/graphql", NULL, false);
    request("acme.atlassian.net/a%2fb", "https://acme.atlassian.net/a%2fb/gateway/api/graphql", NULL, false);
    request("acme.atlassian.net/a b", "https://acme.atlassian.net/a%20b/gateway/api/graphql", NULL, false);
    request("acme.atlassian.net/#fragment text", "https://acme.atlassian.net/#fragment%20text/gateway/api/graphql", NULL, false);
    request("host?bad=%GG", "https://host?bad=%GG/gateway/api/graphql", NULL, false);
    request("host?q=no such host", "https://host?q=no such host/gateway/api/graphql", NULL, true);
    request("no%20such%20host:pwd@host", "https://no%20such%20host:pwd@host/gateway/api/graphql", NULL, true);
    request("no%20such%20host:@host", "https://no%20such%20host:@host/gateway/api/graphql", NULL, true);
    request("no%20such%20host@host", "https://no%20such%20host@host/gateway/api/graphql", NULL, false);
    request("%6Eo%20such%20host:pwd@host", "https://no%20such%20host:pwd@host/gateway/api/graphql", NULL, true);
    request("user:no%20such%20host@host", "https://user:no%20such%20host@host/gateway/api/graphql", NULL, false);
    request("host:abc", NULL, "invalid port \":abc\" after host", false);
    request("[::1", NULL, "missing ']' in host", false);
    request("x[::1]", NULL, "invalid IP-literal", false);
    request("[127.0.0.1]", NULL, "invalid IP-literal", false);
    request("host/a%GG", NULL, "invalid URL escape \"%GG\"", false);
    request("host/#bad%GG", NULL, "invalid URL escape \"%GG\"", false);

    br_jiratoken_target target = {0}; char *error = NULL;
    CHECK(br_jiratoken_target_init(SLICE("host/#\0tail"), true, &target, &error) == 0 && !error && !target.cause);
    CHECK(!strcmp(target.url, "https://host/#%00tail/gateway/api/graphql"));
    CHECK(target.original.len > strlen((const char *)target.original.data));
    br_jiratoken_target_clear(&target);
    CHECK(br_jiratoken_target_init(SLICE("host\0bad"), true, &target, &error) == 0 && !error && !target.url);
    CHECK(target.cause && !strcmp(target.cause, "net/url: invalid control character in URL"));
    br_jiratoken_target_clear(&target);
    CHECK(br_jiratoken_target_init(SLICE("[::bad::]"), false, &target, &error) == 0 && !error && !target.url);
    CHECK(target.original.data && target.cause && !strcmp(target.cause, "net/http: nil Context"));
    br_jiratoken_target_clear(&target);
    CHECK(br_jiratoken_target_init(SLICE("[::bad::]"), true, &target, &error) == -1 && error);
    CHECK(!strcmp(error, "unsupported: Jira invalid-IP diagnostic projection") && !target.original.data && !target.cause);
    free(error); error = NULL;
    CHECK(br_jiratoken_target_init(SLICE("host:\xc3\xa9"), true, &target, &error) == -1 && error);
    CHECK(!strcmp(error, "unsupported: Jira non-ASCII URL diagnostic quoting") && !target.original.data && !target.cause);
    free(error); error = NULL;
    br_bytes host = {0};
    CHECK(br_jiratoken_endpoint_host((br_slice){NULL, 1}, &host, &error) == -1 && error);
    free(error); error = NULL;
    CHECK(br_jiratoken_target_init(SLICE("host"), true, NULL, &error) == -1 && error);
    free(error);
    return test_finish("Jira byte EndpointHost/request construction/legacy colons/source wrapper facts/lifetimes");
}
