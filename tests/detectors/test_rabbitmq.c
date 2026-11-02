/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/rabbitmq.c"

static void check_socket_io(void)
{
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    unsigned char args[501] = {0}, frame[512];
    CHECK(send_method(pair[0], 10, 11, args, sizeof(args)) != 0);
    CHECK(send_method(pair[0], 10, 11, args, sizeof(args) - 1) == 0);
    CHECK(read_full(pair[1], frame, sizeof(frame)) == 0 && frame[511] == 0xCE);
    CHECK(close(pair[1]) == 0);
    struct sigaction before, after;
    CHECK(sigaction(SIGPIPE, NULL, &before) == 0);
    CHECK(write_all(pair[0], args, 1) == -1 && errno == EPIPE);
    CHECK(sigaction(SIGPIPE, NULL, &after) == 0 && before.sa_handler == after.sa_handler);
    sigset_t block, previous, pending;
    CHECK(sigemptyset(&block) == 0 && sigaddset(&block, SIGPIPE) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, &block, &previous) == 0);
    CHECK(raise(SIGPIPE) == 0);
    CHECK(write_all(pair[0], args, 1) == -1 && errno == EPIPE);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1);
    int caught;
    CHECK(sigwait(&block, &caught) == 0 && caught == SIGPIPE);
    CHECK(pthread_sigmask(SIG_SETMASK, &previous, NULL) == 0);
    CHECK(close(pair[0]) == 0);
    char *cause = NULL;
    int fd = -1;
    CHECK(dial_numeric("192.0.2.1", "65536", &fd, &cause) == 1 && cause && fd == -1);
    free(cause);
}

int main(void)
{
    check_socket_io();
    const br_detector *detector = NULL;
    char *error = NULL;
    CHECK(br_rabbitmq_init(&detector, &error) == 0 && !error);
    CHECK(detector->type == 903 && !strcmp(detector->keywords[0], "amqp"));
    CHECK(detector->max_credential_span == -1);
    const char *url = "amqp://user:s3cret@192.0.2.1/vhost";
    char input[160];
    snprintf(input, sizeof(input), "amqp %s", url);
    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1 && !results.items[0].verified);
    CHECK(!strcmp(results.items[0].redacted, "amqp://user:********@192.0.2.1/vhost"));
    br_results_clear(&results);
    const char *repeated = "amqp://abc:abc@abc.net/abc";
    results = test_scan(detector, NULL, false, repeated, strlen(repeated));
    CHECK(results.len == 1 && !strcmp(results.items[0].redacted,
                                    "amqp://********:********@********.net/********"));
    br_results_clear(&results);
    snprintf(input, sizeof(input), "%s\n%s", url, url);
    results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == 1);
    br_results_clear(&results);
    const char *local = "amqp://user:s3cret@localhost/vhost";
    results = test_scan(detector, NULL, false, local, strlen(local));
    CHECK(!results.len);
    br_results_clear(&results);
    const char *example = "amqp://user:s3cret@example.com/vhost";
    results = test_scan(detector, NULL, false, example, strlen(example));
    CHECK(!results.len);
    br_results_clear(&results);
    const char *stars = "amqp://user:***@192.0.2.1/vhost";
    results = test_scan(detector, NULL, false, stars, strlen(stars));
    CHECK(!results.len);
    br_results_clear(&results);
    const char *dollar = "amqp://user:$secret@192.0.2.1/vhost";
    results = test_scan(detector, NULL, true, dollar, strlen(dollar));
    CHECK(!results.len);
    br_results_clear(&results);
    results = test_scan(detector, NULL, true, url, strlen(url));
    CHECK(results.len == 1 && results.items[0].verification_error);
    CHECK(strstr(results.items[0].verification_error, "network is unreachable") ||
          strstr(results.items[0].verification_error, "connect"));
    CHECK(!strstr(results.items[0].verification_error, "s3cret"));
    br_results_clear(&results);
    return test_finish("RabbitMQ");
}
