/* SPDX-License-Identifier: AGPL-3.0-only */
#include "first_batch.h"
#include "second_batch.h"
#include "third_batch.h"
#include "fourth_batch.h"
#include "fifth_batch.h"

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
    static const br_detector *implemented[19];
    static bool initialized;
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return fail(error, "invalid detector registry outputs");
    if (!initialized) {
        const br_detector *const *first = NULL, *const *second = NULL;
        const br_detector *const *third = NULL, *const *fourth = NULL, *const *fifth = NULL;
        size_t nfirst = 0, nsecond = 0, nthird = 0, nfourth = 0, nfifth = 0;
        if (br_first_batch(&first, &nfirst, error) != 0 ||
            br_second_batch(&second, &nsecond, error) != 0 ||
            br_third_batch(&third, &nthird, error) != 0 ||
            br_fourth_batch(&fourth, &nfourth, error) != 0 ||
            br_fifth_batch(&fifth, &nfifth, error) != 0) return -1;
        if (nfirst != 3 || nsecond != 4 || nthird != 4 || nfourth != 4 || nfifth != 4)
            return fail(error, "unexpected compiled detector batch sizes");
        /* Batches retain pinned defaults-list order, including disabled entries. */
        for (size_t i = 0; i < nfirst; ++i) implemented[i] = first[i];
        for (size_t i = 0; i < nsecond; ++i) implemented[nfirst + i] = second[i];
        for (size_t i = 0; i < nthird; ++i) implemented[nfirst + nsecond + i] = third[i];
        for (size_t i = 0; i < nfourth; ++i) implemented[nfirst + nsecond + nthird + i] = fourth[i];
        for (size_t i = 0; i < nfifth; ++i) implemented[nfirst + nsecond + nthird + nfourth + i] = fifth[i];
        initialized = true;
    }
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_detector_is_default(const br_detector *detector, const br_json *feature_flags)
{
    (void)feature_flags; /* None of these nineteen implementations has a feature gate. */
    return br_first_batch_is_default(detector) || br_second_batch_is_default(detector) ||
           br_third_batch_is_default(detector) || br_fourth_batch_is_default(detector) ||
           br_fifth_batch_is_default(detector);
}

const char *br_detector_type_name(int32_t type)
{
    switch (type) {
    case 125: return "AirbrakeProjectKey";
    case 126: return "AirbrakeUserKey";
    case 136: return "AdobeIO";
    case 197: return "Agora";
    case 239: return "Abyssale";
    case 277: return "Airship";
    case 303: return "Accuweather";
    case 384: return "Abstract";
    case 390: return "AdafruitIO";
    case 431: return "Adzuna";
    case 498: return "AirVisual";
    case 521: return "AbuseIPDB";
    case 693: return "Aeroworkflow";
    case 802: return "Aha";
    case 907: return "Alchemy";
    case 917: return "Aiven";
    case 1014: return "AirtableOAuth";
    case 1015: return "AirtablePersonalAccessToken";
    default: return NULL;
    }
}
