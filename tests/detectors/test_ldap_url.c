/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/ldap_private.h"
#include "../../src/go_url.h"
#include "../support/detector_test.h"

static int parse_status;
static bool allocation_failure;
static int controlled_parse(br_slice input, br_go_url_parts *parts,
                             br_go_url_error *ordinary, char **fatal)
{
    if (!parse_status) return br_go_url_parse(input, parts, ordinary, fatal);
    *parts = (br_go_url_parts){.host_storage = {(unsigned char *)strdup("owned"), 5}};
    CHECK(parts->host_storage.data != NULL);
    *ordinary = (br_go_url_error){.kind = BR_GO_URL_ESCAPE};
    if (fatal) *fatal = NULL;
    return parse_status;
}
static void *controlled_malloc(size_t size)
{
    return allocation_failure ? NULL : malloc(size);
}
#define br_ldap_url_string checked_url_string
#define br_go_url_parse controlled_parse
#define malloc controlled_malloc
#include "../../src/detectors/ldap_url.c"
#undef malloc
#undef br_go_url_parse
#undef br_ldap_url_string

static void projection(br_slice input, const char *expected)
{
    br_bytes out = {0}; bool accepted = false; char *fatal = NULL;
    CHECK(br_ldap_url_string(input, &out, &accepted, &fatal) == 0 && !fatal);
    CHECK(accepted == (expected != NULL));
    if (expected) {
        CHECK(out.data && out.len == strlen(expected) && !memcmp(out.data, expected, out.len));
        CHECK(out.data && out.data[out.len] == 0);
        CHECK(out.data != input.data);
    } else CHECK(!out.data && !out.len);
    free(out.data); free(fatal);
}

int main(void)
{
    /* Expected projections follow pinned Go1.26.7 Parse, Userinfo.String,
     * URL.String, EscapedPath/Fragment and urlstrictcolons=0. No I/O oracle. */
    static const struct { const char *input, *expected; } cases[] = {
        {"LDAP://Host/OU=IT,DC=Business,DC=com", "ldap://Host/OU=IT,DC=Business,DC=com"},
        {"LdApS://Host:636/dc=example,dc=com", "ldaps://Host:636/dc=example,dc=com"},
        {"ldap://127.0.0.1", "ldap://127.0.0.1"},
        {"ldap://mydomain.test:389", "ldap://mydomain.test:389"},
        {"ldap://[fe80::4bd1]:5060", "ldap://[fe80::4bd1]:5060"},
        {"ldaps://[fe80:4049:92ff:fe44:4bd1]:5060", NULL},
        {"ldap://[::ffff:192.0.2.1]", "ldap://[::ffff:192.0.2.1]"},
        {"ldap://[::1%25eth0]/", "ldap://[::1%25eth0]/"},
        {"ldap://host:", "ldap://host:"},
        {"ldap://host:999999", "ldap://host:999999"},
        {"ldap://a:b:389", "ldap://a:b:389"},
        {"ldap://host:bad/path", NULL},
        {"ldap://[127.0.0.1]/", NULL},
        {"ldap://host%2f/path", NULL},
        {"ldap://host%25/path", "ldap://host%25/path"},
        {"ldap://u%73er:p%3ass@Host/", "ldap://user:p%3Ass@Host/"},
        {"ldap://user:pa:ss@Host/", "ldap://user:pa%3Ass@Host/"},
        {"ldap://u@ser:@Host/", "ldap://u%40ser:@Host/"},
        {"ldap://@Host/", "ldap://@Host/"},
        {"ldap://:p@/x", "ldap://:p@/x"},
        {"ldap://host/a%2fb/%2e", "ldap://host/a%2fb/%2e"},
        {"ldap://host/a b", "ldap://host/a%20b"},
        {"ldap://host/a\xc3\xa9/%2f", "ldap://host/a%C3%A9//"},
        {"ldap://host/[!()*]", "ldap://host/[!()*]"},
        {"ldap://host/%ff", "ldap://host/%ff"},
        {"ldap://host/%", NULL},
        {"ldap://host/a\vname", NULL},
        {"ldap://host/a?bad=%zz;givenName?sub?(uid=john.doe)", "ldap://host/a?bad=%zz;givenName?sub?(uid=john.doe)"},
        {"ldap://ds.example.com:389/dc=example,dc=com?givenName,sn,cn?sub?(uid=john.doe)", "ldap://ds.example.com:389/dc=example,dc=com?givenName,sn,cn?sub?(uid=john.doe)"},
        {"LDAP://?query", "ldap:?query"},
        {"LDAPS://#fragment", "ldaps:#fragment"},
        {"ldap://?", "ldap:?"},
        {"ldap://??", "ldap:??"},
        {"ldap:///path", "ldap:///path"},
        {"ldap:////path", "ldap:////path"},
        {"ldap://host/path?#", "ldap://host/path?"},
        {"ldap://host/path#%2f", "ldap://host/path#%2f"},
        {"ldap://host/path#x\xc3\xa9%2f", "ldap://host/path#x%C3%A9/"},
        {"ldap://host/path#%", NULL},
        {"ldap\xc5\xbf://host/path", NULL},
        {"ldap://m\xc3\xbcnich/path", "ldap://m%C3%BCnich/path"}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i)
        projection((br_slice){(const unsigned char *)cases[i].input, strlen(cases[i].input)}, cases[i].expected);
    static const unsigned char nul_fragment[] = "ldap://host/path#pre\0post";
    projection((br_slice){nul_fragment, sizeof(nul_fragment) - 1}, "ldap://host/path#pre%00post");
    static const unsigned char nul_path[] = "ldap://host/pre\0post";
    projection((br_slice){nul_path, sizeof(nul_path) - 1}, NULL);
    static const unsigned char invalid_fragment[] = "ldap://host/#\xff";
    projection((br_slice){invalid_fragment, sizeof(invalid_fragment) - 1}, "ldap://host/#%FF");

    br_slice input = {(const unsigned char *)"ldap://host", 11};
    br_bytes out = {0}; bool accepted = false; char *fatal = NULL;
    for (int status = -1; status <= 1; status += 2) {
        parse_status = status;
        CHECK(checked_url_string(input, &out, &accepted, &fatal) == status);
        CHECK(!out.data && !out.len && !accepted && !fatal);
    }
    parse_status = 0; allocation_failure = true;
    CHECK(checked_url_string(input, &out, &accepted, &fatal) != 0 && fatal && !accepted && !out.data);
    free(fatal); fatal = NULL; allocation_failure = false;
    CHECK(br_ldap_url_string(input, NULL, &accepted, &fatal) != 0 && fatal);
    free(fatal); fatal = NULL;
    CHECK(br_ldap_url_string(input, &out, NULL, &fatal) != 0 && fatal && !out.data);
    free(fatal); fatal = NULL;
    CHECK(br_ldap_url_string((br_slice){NULL, 1}, &out, &accepted, &fatal) != 0 && fatal && !accepted && !out.data);
    free(fatal); fatal = NULL;
    CHECK(br_ldap_url_string((br_slice){(const unsigned char *)"ldap:opaque", 11}, &out, &accepted, &fatal) != 0 && fatal && !accepted && !out.data);
    free(fatal);
    return test_finish("LDAP source URL projection, empty-authority scheme routing and fatal propagation");
}
