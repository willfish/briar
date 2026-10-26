/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2,
 * pkg/detectors/azureapimanagement/repositorykey/repositorykey.go. */
#include "detectors.h"
#include "azureapimanagement_repositorykey.h"
#include "captures.h"
#include "findings.h"
#include "host_cache.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    br_regex *host, *password;
    br_azureapim_git_run_fn run;
    void *user;
} apim_repo_patterns;
static apim_repo_patterns apim_repo_compiled;
static br_host_cache apim_repo_invalid_hosts = BR_HOST_CACHE_INIT;

static int apim_repo_fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

void br_azureapimanagement_repositorykey_set_git_runner(br_azureapim_git_run_fn run, void *user)
{
    apim_repo_compiled.run = run;
    apim_repo_compiled.user = user;
}

static void apim_repo_git_clear(br_azureapim_git_result *result)
{
    free(result->output.data);
    free(result->leaf_error);
    memset(result, 0, sizeof(*result));
}

static bool apim_repo_digit(unsigned char c) { return c >= '0' && c <= '9'; }

/* FindString(`\d+\.\d+\.\d+`), including matches after embedded NUL.
 * Only the first triplet is significant; patch digits are not interpreted. */
static bool apim_repo_version(br_slice output, br_slice *version, br_slice *major, br_slice *minor)
{
    for (size_t i = 0; i < output.len; ++i) {
        if (!apim_repo_digit(output.data[i])) continue;
        size_t a = i;
        while (a < output.len && apim_repo_digit(output.data[a])) ++a;
        if (a + 1 < output.len && output.data[a] == '.' && apim_repo_digit(output.data[a + 1])) {
            size_t b = a + 1;
            while (b < output.len && apim_repo_digit(output.data[b])) ++b;
            if (b + 1 < output.len && output.data[b] == '.' && apim_repo_digit(output.data[b + 1])) {
                size_t end = b + 1;
                while (end < output.len && apim_repo_digit(output.data[end])) ++end;
                *version = (br_slice){output.data + i, end - i};
                *major = (br_slice){output.data + i, a - i};
                *minor = (br_slice){output.data + a + 1, b - a - 1};
                return true;
            }
        }
        i = a - 1;
    }
    return false;
}

/* Atoi errors are ignored upstream. All tokens are positive decimal digits:
 * an overflowing minor saturates above 20, while an overflowing major != 2. */
static bool apim_repo_supported_version(br_slice major, br_slice minor)
{
    while (major.len > 1 && *major.data == '0') { ++major.data; --major.len; }
    while (minor.len > 1 && *minor.data == '0') { ++minor.data; --minor.len; }
    return major.len == 1 && *major.data == '2' &&
           (minor.len > 2 || (minor.len == 2 && memcmp(minor.data, "20", 2) >= 0));
}

static int apim_repo_version_error(br_slice version, char **out)
{
    static const char prefix[] = "git version is ";
    static const char suffix[] = ", but must be greater than or equal to 2.20.0, and less than 3.0.0";
    size_t overhead = sizeof(prefix) - 1 + sizeof(suffix);
    if (version.len > SIZE_MAX - overhead) return -1;
    *out = malloc(version.len + overhead);
    if (!*out) return -1;
    memcpy(*out, prefix, sizeof(prefix) - 1);
    memcpy(*out + sizeof(prefix) - 1, version.data, version.len);
    memcpy(*out + sizeof(prefix) - 1 + version.len, suffix, sizeof(suffix));
    return 0;
}

static int apim_repo_remote(const char *host, const char *password, char **out)
{
    static const char prefix[] = "https://apim:";
    size_t host_len = strlen(host), password_len = strlen(password);
    if (host_len > SIZE_MAX - sizeof(prefix) - 1) return -1;
    size_t base = sizeof(prefix) + 1 + host_len;
    if (password_len > (SIZE_MAX - base) / 3) return -1;
    char *remote = malloc(base + 3 * password_len);
    if (!remote) return -1;
    size_t at = sizeof(prefix) - 1;
    memcpy(remote, prefix, at);
    /* url.Parse(bareHost) leaves Host empty and Path=bareHost, but setting
     * UserPassword/Scheme serializes to this authority. In the captured
     * password alphabet only '/' needs userinfo escaping, not '&', '+' or '='. */
    for (size_t i = 0; i < password_len; ++i) {
        if (password[i] == '/') { memcpy(remote + at, "%2F", 3); at += 3; }
        else remote[at++] = password[i];
    }
    remote[at++] = '@';
    memcpy(remote + at, host, host_len + 1);
    *out = remote;
    return 0;
}

static int apim_repo_verify(const apim_repo_patterns *patterns, const char *host,
                             const char *password, br_result *result, bool *invalid_host, char **error)
{
    br_slice redacted = {(const unsigned char *)host, strlen(host)};
    if (!patterns->run)
        return br_result_set_verification_error(result,
            "unsupported: native Git execution for Azure API Management repository keys", &redacted, 1);
    br_azureapim_git_result command = {0};
    const char *cause = NULL;
    char *version_error = NULL, *remote = NULL;
    int rc = 0;
    const char *const check[] = {"git"};
    int ran = patterns->run(patterns->user, check, 1, BR_AZUREAPIM_GIT_DISCARD, &command);
    if (ran < 0) goto resource;
    if (command.not_found) {
        cause = "'git' command not found in $PATH. Make sure git is installed and included in $PATH";
        goto finish;
    }
    /* The no-argument command may fail (normally usage/exit 1). Ignore it. */
    apim_repo_git_clear(&command);
    const char *const version_args[] = {"git", "--version"};
    ran = patterns->run(patterns->user, version_args, 2, BR_AZUREAPIM_GIT_STDOUT, &command);
    if (ran < 0) goto resource;
    if (ran) {
        /* The source wraps this in "failed to check git version: %w", but
         * SetVerificationError unwraps it before recording the leaf cause. */
        cause = command.leaf_error ? command.leaf_error : "Git command failed";
        goto finish;
    }
    br_slice version, major, minor;
    if ((!command.output.data && command.output.len) ||
        !apim_repo_version((br_slice){command.output.data, command.output.len}, &version, &major, &minor)) {
        rc = apim_repo_fail(error, "unsupported upstream panic: Azure API Management Git version has no numeric triplet");
        goto cleanup;
    }
    if (!apim_repo_supported_version(major, minor)) {
        if (apim_repo_version_error(version, &version_error)) goto resource;
        cause = version_error;
        goto finish;
    }
    apim_repo_git_clear(&command);
    if (apim_repo_remote(host, password, &remote)) goto resource;
    const char *const args[] = {"git", "ls-remote", remote, "--quiet",
                               "TRUFFLEHOG_CHECK_GIT_REMOTE_URL_REACHABILITY"};
    ran = patterns->run(patterns->user, args, 5, BR_AZUREAPIM_GIT_COMBINED, &command);
    if (ran < 0) goto resource;
    if (!ran) result->verified = true;
    else {
        static const unsigned char auth[] = "Authentication failed";
        static const unsigned char dns[] = "Could not resolve host";
        br_slice output = {command.output.data, command.output.len};
        if (!output.data && output.len) {
            rc = apim_repo_fail(error, "invalid Azure API Management Git output");
            goto cleanup;
        }
        if (br_slice_find(output, (br_slice){auth, sizeof(auth) - 1}, 0) != SIZE_MAX) {
            /* Authentication takes precedence even when the DNS marker is present. */
        } else if (br_slice_find(output, (br_slice){dns, sizeof(dns) - 1}, 0) != SIZE_MAX)
            *invalid_host = true;
        else cause = command.leaf_error ? command.leaf_error : "Git command failed";
    }
finish:
    rc = br_result_set_verification_error(result, cause, &redacted, 1);
    goto cleanup;
resource:
    rc = apim_repo_fail(error, "resource failure running Azure API Management Git verification");
cleanup:
    apim_repo_git_clear(&command);
    free(version_error);
    free(remote);
    return rc;
}

static int apim_repo_scan(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                           br_slice input, br_results *out, char **error)
{
    (void)ctx; /* Upstream uses exec.Command, not CommandContext. */
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len))
        return apim_repo_fail(error, "invalid Azure API Management repository key scan arguments");
    const apim_repo_patterns *patterns = detector->state;
    if (!patterns->host || !patterns->password)
        return apim_repo_fail(error, "uninitialized Azure API Management repository key detector");
    size_t original_len = out->len;
    br_captures hosts = {0}, passwords = {0};
    int rc = br_captures_find(patterns->host, input, &hosts, true, error);
    if (!rc) rc = br_captures_find(patterns->password, input, &passwords, true, error);
    /* TrimSpace is a no-op for both alphabets. Go maps deduplicate captures;
     * retain first-occurrence order as one possible map iteration order. */
    for (size_t h = 0; !rc && h < hosts.len; ++h) {
        const char *host = hosts.items[h];
        for (size_t p = 0; !rc && p < passwords.len; ++p) {
            if (verify) {
                bool cached = false;
                if (br_host_cache_contains(&apim_repo_invalid_hosts, host, &cached)) {
                    rc = apim_repo_fail(error, "cannot read Azure API Management invalid-host cache");
                    break;
                }
                if (cached) break;
            }
            br_result result = {0};
            bool invalid_host = false;
            const char *password = passwords.items[p];
            if (br_finding_pair(&result, detector->type, password, "password", host, "url"))
                rc = apim_repo_fail(error, "out of memory creating Azure API Management repository key result");
            else {
                /* Raw is password, but upstream RawV2 reverses the pair. */
                memcpy(result.raw_v2.data, host, hosts.lengths[h]);
                memcpy(result.raw_v2.data + hosts.lengths[h], password, passwords.lengths[p]);
                if (verify) rc = apim_repo_verify(patterns, host, password, &result, &invalid_host, error);
                if (!rc && invalid_host) {
                    if (br_host_cache_add(&apim_repo_invalid_hosts, host))
                        rc = apim_repo_fail(error, "cannot cache Azure API Management invalid host");
                } else if (!rc && br_results_push(out, &result))
                    rc = apim_repo_fail(error, "out of memory appending Azure API Management repository key result");
            }
            br_result_clear(&result);
            if (invalid_host) break; /* Suppress this candidate and remaining passwords for this host. */
        }
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&hosts);
    br_captures_clear(&passwords);
    return rc;
}

static const char *const apim_repo_keywords[] = {"azure", ".scm.azure-api.net"};
static const char *const apim_repo_host_prefixes[] = {"azure", "url"};
static const char *const apim_repo_password_prefixes[] = {"azure", "password"};
static const br_detector apim_repo_detector = {
    .type = 1018, .version = 0, .name = "AzureApiManagementRepositoryKey", .custom_name = "",
    .description = "Azure API Management Repository Keys provide access to the API Management (APIM) configuration repository, "
                   "allowing users to directly interact with and modify API definitions, policies, and settings. These keys "
                   "enable programmatic access to APIM's Git-based repository, where configurations can be cloned, edited, "
                   "and pushed back to apply changes. They are primarily used for managing API configurations as code, "
                   "automating deployments, and synchronizing APIM settings across environments.",
    .keywords = apim_repo_keywords, .nkeywords = 2,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &apim_repo_compiled, .scan = apim_repo_scan,
};

int br_azureapimanagement_repositorykey_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return apim_repo_fail(error, "invalid Azure API Management repository key detector output");
    *out = NULL;
    if (!apim_repo_compiled.host && br_regex_compile_prefixed(apim_repo_host_prefixes, 2,
        "([a-z0-9][a-z0-9-]{0,48}[a-z0-9]\\.scm\\.azure-api\\.net)", &apim_repo_compiled.host, error)) return -1;
    if (!apim_repo_compiled.password && br_regex_compile_prefixed(apim_repo_password_prefixes, 2,
        "\\b(git&[0-9]{12}&[a-zA-Z0-9/+]{85}[a-zA-Z0-9]==)", &apim_repo_compiled.password, error)) return -1;
    *out = &apim_repo_detector;
    return 0;
}
