/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/portainertoken.c"
#include <sys/wait.h>

static void check_broken_diagnostic_pipe(void)
{
    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    CHECK(close(pipefd[0]) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 || close(pipefd[1])) _exit(1);
        char *url = NULL, *error = NULL;
        bool valid = false;
        static const unsigned char rejected[] = "http://%zz";
        int rc = request_url((br_slice){rejected, sizeof(rejected) - 1}, &url, &valid, &error);
        bool failed = rc != 0 && !url && !valid && error;
        free(error); free(url);
        _exit(failed ? 0 : 1);
    }
    CHECK(close(pipefd[1]) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static const char *key = "ptr_abcdefghijABCDEFGHIJ";
static const char *endpoint = "https://portainer.example:9443/api/old";

static void inspect(test_http *http, const br_scan_ctx *ctx, const br_http_request *request)
{
    (void)http; (void)ctx;
    CHECK(request->profile == BR_HTTP_DETECTOR_LOCAL && request->timeout_ms == 10000);
    CHECK(!strcmp(request->method, "GET"));
    CHECK(!strcmp(request->url, "https://portainer.example:9443/api/stacks"));
    CHECK(!strcmp(request->headers[0].name, "X-API-Key") && !strcmp(request->headers[0].value, key));
    CHECK(!strcmp(request->headers[1].name, "User-Agent"));
}

int main(void)
{
    check_broken_diagnostic_pipe();
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_portainertoken_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 943 && detector->max_credential_span == 1024);
    char input[192];
    snprintf(input, sizeof(input), "portainertoken %s portainer %s", key, endpoint);
    test_http http = {.response = {.status = 200}, .inspect = inspect};
    br_transport transport = test_transport(&http);
    br_scan_ctx ctx = {.transport = &transport};
    br_results results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.len == 1 && results.items[0].verified);
    CHECK(results.items[0].raw.len == strlen(key));
    CHECK(results.items[0].raw_v2.len == strlen(key) + strlen(endpoint));
    br_json *part = NULL;
    CHECK(json_object_object_get_ex(results.items[0].secret_parts, "url", &part));
    CHECK(!strcmp(json_object_get_string(part), endpoint));
    br_results_clear(&results);
    http.response.status = 401;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(!results.items[0].verified && !results.items[0].verification_error);
    br_results_clear(&results);
    http.response.status = 403;
    results = test_scan(detector, &ctx, true, input, strlen(input));
    CHECK(results.items[0].verification_error && strstr(results.items[0].verification_error, "unexpected HTTP response status 403"));
    CHECK(!strstr(results.items[0].verification_error, key));
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    snprintf(input, sizeof(input), "portainertoken %s portainer http://%%zz", key);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(!results.len);
    br_results_clear(&results);
    return test_finish("PortainerToken");
}
