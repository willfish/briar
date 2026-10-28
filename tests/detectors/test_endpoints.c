/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/endpoints.h"
#include "../support/detector_test.h"

static size_t fail_malloc_size;
void *malloc(size_t size)
{
    if (fail_malloc_size && size == fail_malloc_size) { fail_malloc_size = 0; return NULL; }
    return calloc(1, size);
}

static void expect_bytes(const br_byte_endpoints *list, size_t index, br_slice expected)
{
    CHECK(index < list->len);
    if (index >= list->len) return;
    br_slice actual = br_byte_endpoints_at(list, index);
    CHECK(actual.len == expected.len);
    if (actual.len == expected.len && actual.len) CHECK(!memcmp(actual.data, expected.data, actual.len));
    CHECK(list->items[index].data[actual.len] == 0);
}

static void byte_endpoints(void)
{
    br_byte_endpoints list = {0}; char *error = NULL;
    unsigned char borrowed[] = {'h', 'o', 's', 't', 0, 'A'};
    static const unsigned char a[] = "host\0A", b[] = "host\0B";
    CHECK(!br_byte_endpoints_push(&list, (br_slice){borrowed, sizeof(borrowed)}, true, &error) && !error);
    borrowed[0] = 'X';
    expect_bytes(&list, 0, (br_slice){a, sizeof(a) - 1});
    CHECK(!br_byte_endpoints_push(&list, (br_slice){a, sizeof(a) - 1}, true, &error) && !error);
    CHECK(list.len == 1);
    CHECK(!br_byte_endpoints_push(&list, (br_slice){b, sizeof(b) - 1}, true, &error) && !error);
    CHECK(!br_byte_endpoints_push(&list, (br_slice){a, 4}, true, &error) && !error);
    CHECK(!br_byte_endpoints_push(&list, (br_slice){0}, true, &error) && !error);
    CHECK(!br_byte_endpoints_push(&list, (br_slice){0}, true, &error) && !error);
    CHECK(list.len == 4);
    CHECK(!br_byte_endpoints_push(&list, (br_slice){0}, false, &error) && !error);
    CHECK(list.len == 5);
    expect_bytes(&list, 1, (br_slice){b, sizeof(b) - 1});
    expect_bytes(&list, 2, (br_slice){a, 4});
    expect_bytes(&list, 3, (br_slice){0}); expect_bytes(&list, 4, (br_slice){0});
    br_byte_endpoints_clear(&list); CHECK(!list.items && !list.len && !list.cap);

    static const unsigned char unusual[] = "https://a\0\v\xe2\x98\x83.hashicorp.cloud/path";
    br_captures found = {0};
    CHECK(!br_captures_push(&found, (br_slice){unusual, sizeof(unusual) - 1}, false, &error) && !error);
    CHECK(!br_captures_push(&found, (br_slice){b, sizeof(b) - 1}, false, &error) && !error);
    CHECK(!br_captures_push(&found, (br_slice){(const unsigned char *)"configured", 10}, false, &error) && !error);
    CHECK(!br_captures_push(&found, (br_slice){(const unsigned char *)"cloud", 5}, false, &error) && !error);
    const char *configured[] = {"configured", "configured", ""};
    br_endpoints options = {.configured = configured, .nconfigured = 3,
        .cloud = "cloud", .use_cloud = true, .use_found = true};
    CHECK(!br_endpoints_collect_bytes(&options, "default", &found, &list, &error) && !error);
    CHECK(list.len == 7);
    expect_bytes(&list, 0, (br_slice){(const unsigned char *)"configured", 10});
    expect_bytes(&list, 1, (br_slice){0});
    expect_bytes(&list, 2, (br_slice){(const unsigned char *)"cloud", 5});
    found.items[0][0] = 'X';
    expect_bytes(&list, 3, (br_slice){unusual, sizeof(unusual) - 1});
    found.items[0][0] = 'h';
    expect_bytes(&list, 4, (br_slice){b, sizeof(b) - 1});
    expect_bytes(&list, 5, (br_slice){(const unsigned char *)"configured", 10});
    expect_bytes(&list, 6, (br_slice){(const unsigned char *)"cloud", 5});
    br_byte_endpoints_clear(&list);

    options.use_found = options.use_cloud = false;
    CHECK(!br_endpoints_collect_bytes(&options, "default", &found, &list, &error) && !error && list.len == 2);
    br_byte_endpoints_clear(&list);
    CHECK(!br_endpoints_collect_bytes(NULL, "", &found, &list, &error) && !error && list.len == 4);
    expect_bytes(&list, 0, (br_slice){unusual, sizeof(unusual) - 1});
    br_byte_endpoints_clear(&list);
    CHECK(!br_endpoints_collect_bytes(NULL, "default", &found, &list, &error) && !error && list.len == 5);
    expect_bytes(&list, 0, (br_slice){(const unsigned char *)"default", 7});
    br_byte_endpoints_clear(&list);
    options = (br_endpoints){0};
    CHECK(!br_endpoints_collect_bytes(&options, "default", &found, &list, &error) && !error && !list.len);
    options = (br_endpoints){.configured = configured + 2, .nconfigured = 1};
    CHECK(!br_endpoints_collect_bytes(&options, "default", &found, &list, &error) && !error && list.len == 1);
    expect_bytes(&list, 0, (br_slice){0}); br_byte_endpoints_clear(&list);
    options = (br_endpoints){.use_cloud = true};
    CHECK(!br_endpoints_collect_bytes(&options, "default", &found, &list, &error) && !error && list.len == 1);
    br_byte_endpoints_clear(&list); options.cloud = "";
    CHECK(!br_endpoints_collect_bytes(&options, "default", &found, &list, &error) && !error && !list.len);

    const char *invalid[] = {"copied before error", NULL};
    options = (br_endpoints){.configured = invalid, .nconfigured = 2};
    CHECK(br_endpoints_collect_bytes(&options, "", &found, &list, &error) == -1 && error);
    CHECK(!list.items && !list.len && !list.cap); free(error); error = NULL;
    options.configured = NULL;
    CHECK(br_endpoints_collect_bytes(&options, "", &found, &list, NULL) == -1);
    CHECK(!list.items && !list.len && !list.cap);
    options = (br_endpoints){.configured = configured, .nconfigured = 3, .cloud = "cloud", .use_cloud = true};
    fail_malloc_size = 6; /* Fail the cloud copy after two configured entries. */
    CHECK(br_endpoints_collect_bytes(&options, "", &found, &list, &error) == -1 && error);
    CHECK(!fail_malloc_size && !list.items && !list.len && !list.cap && found.len == 4);
    CHECK(error && strstr(error, "out of memory")); free(error); error = NULL;
    CHECK(br_byte_endpoints_push(&list, (br_slice){a, SIZE_MAX}, false, &error) == -1 && error);
    CHECK(!list.items && !list.len && !list.cap); free(error); error = NULL;
    for (size_t i = 0; i < 5; ++i)
        CHECK(!br_captures_push(&found, (br_slice){(const unsigned char *)"cloud", 5}, false, &error) && !error);
    options = (br_endpoints){.use_found = true};
    CHECK(!br_endpoints_collect_bytes(&options, "", &found, &list, &error) && !error && list.len == 9);
    expect_bytes(&list, 8, (br_slice){(const unsigned char *)"cloud", 5});
    br_byte_endpoints_clear(&list); br_captures_clear(&found);
}

static void expect(const br_endpoint_list *list, const char *const *items, size_t count)
{
    CHECK(list->len == count);
    for (size_t i = 0; i < count; ++i) CHECK(!strcmp(list->items[i], items[i]));
}

int main(void)
{
    byte_endpoints();
    br_endpoint_list list = {0};
    char *error = NULL;
    char borrowed[] = "host";
    CHECK(br_endpoint_list_push(&list, borrowed, true, &error) == 0 && !error);
    borrowed[0] = 'X';
    CHECK(!strcmp(list.items[0], "host"));
    CHECK(br_endpoint_list_push(&list, "host", true, &error) == 0 && !error);
    CHECK(br_endpoint_list_push(&list, "HOST", true, &error) == 0 && !error);
    CHECK(br_endpoint_list_push(&list, "", true, &error) == 0 && !error);
    CHECK(br_endpoint_list_push(&list, "", false, &error) == 0 && !error);
    expect(&list, (const char *const[]){"host", "HOST", "", ""}, 4);
    br_endpoint_list_clear(&list);
    CHECK(!list.items && !list.len && !list.cap);

    br_captures found = {0};
    CHECK(br_captures_push(&found, (br_slice){(const unsigned char *)"found", 5}, false, &error) == 0 && !error);
    CHECK(br_captures_push(&found, (br_slice){(const unsigned char *)"cloud", 5}, false, &error) == 0 && !error);
    const char *configured[] = {"found", "found", ""};
    br_endpoints options = {.configured = configured, .nconfigured = 3,
        .cloud = "cloud", .use_cloud = true, .use_found = true};
    CHECK(br_endpoints_validate_configured(&options, &error) == 0 && !error);
    CHECK(br_endpoints_collect(&options, "default", &found, &list, &error) == 0 && !error);
    expect(&list, (const char *const[]){"found", "", "cloud", "found", "cloud"}, 5);
    br_endpoint_list_clear(&list);

    options.use_found = options.use_cloud = false;
    CHECK(br_endpoints_collect(&options, "default", &found, &list, &error) == 0 && !error);
    expect(&list, (const char *const[]){"found", ""}, 2);
    br_endpoint_list_clear(&list);
    CHECK(br_endpoints_collect(NULL, "", &found, &list, &error) == 0 && !error);
    expect(&list, (const char *const[]){"found", "cloud"}, 2);
    br_endpoint_list_clear(&list);
    CHECK(br_endpoints_collect(NULL, "default", &found, &list, &error) == 0 && !error);
    expect(&list, (const char *const[]){"default", "found", "cloud"}, 3);
    br_endpoint_list_clear(&list);

    options = (br_endpoints){0}; /* Flags-only state is not an explicit setter call. */
    CHECK(br_endpoints_collect(&options, "default", &found, &list, &error) == 0 && !error);
    CHECK(!list.len);
    CHECK(br_endpoints_validate_configured(&options, &error) == -1 && error);
    CHECK(!strcmp(error, "at least one endpoint required"));
    free(error); error = NULL;
    const char *empty[] = {""};
    options.configured = empty;
    options.nconfigured = 1;
    CHECK(br_endpoints_validate_configured(&options, &error) == 0 && !error);
    CHECK(br_endpoints_collect(&options, "default", &found, &list, &error) == 0 && !error);
    expect(&list, empty, 1);
    br_endpoint_list_clear(&list);

    options = (br_endpoints){.use_cloud = true};
    CHECK(br_endpoints_collect(&options, "default", &found, &list, &error) == 0 && !error);
    expect(&list, (const char *const[]){"default"}, 1);
    br_endpoint_list_clear(&list);
    options.cloud = "";
    CHECK(br_endpoints_collect(&options, "default", &found, &list, &error) == 0 && !error);
    CHECK(!list.len);
    const char *invalid[] = {"copied before error", NULL};
    options.configured = invalid;
    options.nconfigured = 2;
    CHECK(br_endpoints_collect(&options, "", &found, &list, &error) == -1 && error);
    CHECK(!list.items && !list.len && !list.cap);
    free(error);
    br_captures_clear(&found);
    return test_finish("Endpoint ownership and source collection order");
}
