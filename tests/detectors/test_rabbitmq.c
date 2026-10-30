/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

int br_rabbitmq_init(const br_detector **out, char **error);

int main(void)
{
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
