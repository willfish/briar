/* SPDX-License-Identifier: AGPL-3.0-only */
#define main briar_cli_main
#include "../../src/main.c"
#undef main

static size_t checks;
#define CHECK(expr) do { ++checks; if (!(expr)) { fprintf(stderr, "FAIL CLI I/O:%d: %s\n", __LINE__, #expr); exit(1); } } while (0)

static volatile sig_atomic_t pipe_signals;
static void observe_pipe(int signum) { (void)signum; ++pipe_signals; }

int main(void)
{
    struct sigaction original, action = {.sa_handler = SIG_DFL};
    CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGPIPE, &action, &original) == 0);
    sigset_t block, initial, pending, current;
    CHECK(sigemptyset(&block) == 0 && sigaddset(&block, SIGPIPE) == 0);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &block, &initial) == 0);

    int pair[2];
    CHECK(pipe(pair) == 0);
    CHECK(print_line(pair[1], "prefix: ", "synthetic") == 0);
    char text[32] = {0};
    CHECK(read(pair[0], text, sizeof(text)) == 18 && !strcmp(text, "prefix: synthetic\n"));
    CHECK(close(pair[0]) == 0);
    /* Default SIGPIPE would terminate this fixture if the write were unguarded. */
    CHECK(print_line(pair[1], "", "synthetic") != 0);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &current) == 0 && sigismember(&current, SIGPIPE) == 0);

    action.sa_handler = observe_pipe;
    CHECK(sigaction(SIGPIPE, &action, NULL) == 0);
    CHECK(print_line(pair[1], "", "synthetic") != 0 && pipe_signals == 0);
    struct sigaction after;
    CHECK(sigaction(SIGPIPE, NULL, &after) == 0 && after.sa_handler == observe_pipe);
    CHECK(pthread_sigmask(SIG_BLOCK, &block, NULL) == 0);
    CHECK(raise(SIGPIPE) == 0);
    CHECK(print_line(pair[1], "", "synthetic") != 0);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &current) == 0 && sigismember(&current, SIGPIPE) == 1);
    int caught;
    CHECK(sigwait(&block, &caught) == 0 && caught == SIGPIPE);
    CHECK(close(pair[1]) == 0);
    CHECK(print_line(-1, "", "synthetic") != 0);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &initial, NULL) == 0);
    CHECK(sigaction(SIGPIPE, &original, NULL) == 0);
    br_json *finding = json_tokener_parse("{\"SourceMetadata\":{},\"DetectorType\":239,"
        "\"DetectorName\":\"Abyssale\",\"DecoderName\":\"PLAIN\",\"Raw\":\"sensitive\","
        "\"RawV2\":\"sensitive\",\"Redacted\":\"sensitive\",\"SecretParts\":{\"key\":\"sensitive\"},"
        "\"ExtraData\":{\"key\":\"sensitive\"},\"StructuredData\":{\"key\":\"sensitive\"},"
        "\"VerificationError\":\"sensitive\",\"futureField\":\"sensitive\"}");
    CHECK(finding != NULL);
    br_json *safe = hook_result(finding);
    CHECK(safe != NULL && json_object_object_length(safe) == 4);
    CHECK(strstr(json_object_to_json_string(safe), "sensitive") == NULL);
    CHECK(json_object_object_length(finding) == 12);
    json_object_put(finding);
    CHECK(strstr(json_object_to_json_string(safe), "Abyssale") != NULL);
    json_object_put(safe);
    printf("CLI I/O: %zu assertions, 0 failures\n", checks);
    return 0;
}
