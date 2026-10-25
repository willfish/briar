/* SPDX-License-Identifier: AGPL-3.0-only */
#include "first_batch.h"
#include "second_batch.h"

#include <stdlib.h>
#include <string.h>

static int fail(char **error, const char *message)
{
    if (error) {
        size_t len = strlen(message) + 1;
        *error = malloc(len);
        if (*error) memcpy(*error, message, len);
    }
    return -1;
}

int br_registry(const br_detector *const **out, size_t *count, char **error)
{
    /* Initialization is deliberately pre-worker, as required by ABI revision 1. */
    static const br_detector *implemented[7];
    static bool initialized;
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return fail(error, "invalid detector registry outputs");
    if (!initialized) {
        const br_detector *const *first = NULL, *const *second = NULL;
        size_t nfirst = 0, nsecond = 0;
        if (br_first_batch(&first, &nfirst, error) != 0 ||
            br_second_batch(&second, &nsecond, error) != 0) return -1;
        if (nfirst != 3 || nsecond != 4)
            return fail(error, "unexpected compiled detector batch sizes");
        /* Batches retain pinned defaults-list order, including disabled entries. */
        for (size_t i = 0; i < nfirst; ++i) implemented[i] = first[i];
        for (size_t i = 0; i < nsecond; ++i) implemented[nfirst + i] = second[i];
        initialized = true;
    }
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_detector_is_default(const br_detector *detector, const br_json *feature_flags)
{
    (void)feature_flags; /* None of these seven implementations has a feature gate. */
    return br_first_batch_is_default(detector) || br_second_batch_is_default(detector);
}

const char *br_detector_type_name(int32_t type)
{
    switch (type) {
    case 136: return "AdobeIO";
    case 239: return "Abyssale";
    case 303: return "Accuweather";
    case 384: return "Abstract";
    case 390: return "AdafruitIO";
    case 521: return "AbuseIPDB";
    default: return NULL;
    }
}
