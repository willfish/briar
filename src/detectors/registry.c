/* SPDX-License-Identifier: AGPL-3.0-only */
#include "detectors.h"
#include "fourth_batch.h"
#include "fifth_batch.h"

#include <stdlib.h>
#include <string.h>

typedef int (*detector_factory)(const br_detector **, char **);
static const detector_factory named_factories[] = {
    br_abyssale_init,
    br_abstract_init,
    br_abuseipdb_init,
    br_accuweather_v1_init,
    br_accuweather_v2_init,
    br_adafruitio_init,
    br_adobeio_init,
    br_adzuna_init,
    br_aeroworkflow_init,
    br_agora_init,
    br_aha_init,
};

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
        const br_detector *const *fourth = NULL, *const *fifth = NULL;
        size_t nfourth = 0, nfifth = 0;
        size_t at = 0;
        for (size_t i = 0; i < sizeof(named_factories) / sizeof(named_factories[0]); ++i)
            if (named_factories[i](&implemented[at++], error) != 0) return -1;
        if (br_fourth_batch(&fourth, &nfourth, error) != 0 ||
            br_fifth_batch(&fifth, &nfifth, error) != 0) return -1;
        if (nfourth != 4 || nfifth != 4)
            return fail(error, "unexpected compiled detector batch sizes");
        /* Retain pinned defaults-list order while legacy modules are migrated. */
        for (size_t i = 0; i < nfourth; ++i) implemented[at++] = fourth[i];
        for (size_t i = 0; i < nfifth; ++i) implemented[at++] = fifth[i];
        initialized = true;
    }
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_detector_is_default(const br_detector *detector, const br_json *feature_flags)
{
    (void)feature_flags; /* None of these nineteen implementations has a feature gate. */
    if (detector && (!detector->custom_name || !detector->custom_name[0])) {
        switch (detector->type) {
        case 303: return detector->version == 1 || detector->version == 2;
        case 239: case 521: case 390: case 431: case 693: case 197: case 802:
            return detector->version == 0;
        default: break;
        }
    }
    return br_fourth_batch_is_default(detector) ||
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
