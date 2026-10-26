/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/endpoints.h"
#include "../support/detector_test.h"

static void expect(const br_endpoint_list *list, const char *const *items, size_t count)
{
    CHECK(list->len == count);
    for (size_t i = 0; i < count; ++i) CHECK(!strcmp(list->items[i], items[i]));
}

int main(void)
{
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
