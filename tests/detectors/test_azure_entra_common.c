/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../../src/detectors/azure_entra_common.h"
#include "../support/detector_test.h"

static const char client[] = "a6b39f20-17c4-4d85-9e62-0f3a7b1c5d98";
static const char tenant[] = "8e52bd19-6af3-4c70-92d1-5b04e8c7a639";

static void matching(const char *input, size_t nc, size_t nt, const char *first_client, const char *first_tenant)
{
    br_captures clients = {0}, tenants = {0};
    char *error = NULL;
    CHECK(!br_azure_entra_find_ids((br_slice){(const unsigned char *)input, strlen(input)}, &clients, &tenants, &error) && !error);
    CHECK(clients.len == nc && tenants.len == nt);
    if (first_client) CHECK(!strcmp(clients.items[0], first_client));
    if (first_tenant) CHECK(!strcmp(tenants.items[0], first_tenant));
    br_captures_clear(&clients); br_captures_clear(&tenants);
}

static void inspect_query(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    CHECK(ctx && request->profile == BR_HTTP_SANE && request->detector_type == 1013);
    CHECK(!strcmp(request->method, "GET") && !request->body.len);
    CHECK(!strcmp(request->url, http->user));
}

static void discovery(const char *name, const char *url, int status, bool exists, int send_rc)
{
    test_http http = {.response = {.status = status, .body_error = "ignored discovery body failure"},
        .send_rc = send_rc, .send_error = send_rc ? "synthetic discovery failure" : NULL,
        .inspect = inspect_query, .user = (void *)url};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    bool found = !exists;
    char *error = NULL;
    CHECK(!br_azure_entra_tenant_exists(&ctx, 1013, name, &found, &error) && !error && found == exists);
    CHECK(http.calls == 1 && http.releases == 1);
    http.response.status = exists ? 400 : 200;
    http.send_rc = 0; http.send_error = NULL;
    found = !exists;
    CHECK(!br_azure_entra_tenant_exists(&ctx, 1013, name, &found, &error) && !error && found == exists);
    CHECK(http.calls == 1 && http.releases == 1); /* Cached false is not a miss. */
}

int main(void)
{
    char *error = NULL;
    CHECK(!br_azure_entra_common_init(&error) && !error);
    CHECK(!br_azure_entra_common_init(&error) && !error);
    matching("client ID A6B39F20-17C4-4D85-9E62-0F3A7B1C5D98\nclient_id a6b39f20-17c4-4d85-9e62-0f3a7b1c5d98\ntenant_id 8E52BD19-6AF3-4C70-92D1-5B04E8C7A639", 1, 1, client, tenant);
    matching("https://8e52bd19-6af3-4c70-92d1-5b04e8c7a639", 0, 1, NULL, tenant);
    matching("X-AnchorMailbox: synthetic@8e52bd19-6af3-4c70-92d1-5b04e8c7a639", 0, 1, NULL, tenant);
    matching("/8e52bd19-6af3-4c70-92d1-5b04e8c7a639/oauth2/v2.0", 0, 1, NULL, tenant);
    matching("client_id DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF\nclient_id aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaababc", 0, 0, NULL, NULL);
    matching("First.onmicrosoft.com first.onmicrosoft.com First.onmicrosoft.com", 0, 2, NULL, "First.onmicrosoft.com");
    char gap[160];
    memcpy(gap, "tenant", 6); memset(gap + 6, '\r', 60); memcpy(gap + 66, tenant, sizeof(tenant));
    matching(gap, 0, 1, NULL, tenant);
    discovery("positive-source.onmicrosoft.com", "https://login.microsoftonline.com/positive-source.onmicrosoft.com/.well-known/openid-configuration", 200, true, 0);
    discovery("negative-source.onmicrosoft.com", "https://login.microsoftonline.com/negative-source.onmicrosoft.com/.well-known/openid-configuration", 400, false, 0);
    discovery("failed-source.onmicrosoft.com", "https://login.microsoftonline.com/failed-source.onmicrosoft.com/.well-known/openid-configuration", 0, false, 1);
    bool exists = true;
    CHECK(br_azure_entra_tenant_exists(NULL, 1013, NULL, &exists, &error) == -1 && error && !exists);
    free(error);
    return test_finish("Azure Entra IDs and positive/negative tenant discovery");
}
