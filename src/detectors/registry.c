/* SPDX-License-Identifier: AGPL-3.0-only */
#include "detectors.h"

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
    br_airbrakeprojectkey_init,
    br_airbrakeuserkey_init,
    br_airship_init,
    br_airtableoauth_init,
    br_airtablepersonalaccesstoken_init,
    br_airvisual_init,
    br_aiven_init,
    br_alchemy_init,
    br_alconost_init,
    br_alegra_init,
    br_aletheiaapi_init,
    br_algoliaadminkey_init,
    br_alibaba_init,
    br_alienvault_init,
    br_allsports_init,
    br_amadeus_init,
    br_ambee_init,
    br_amplitudeapikey_init,
    br_anthropic_init,
    br_anypoint_init,
    br_anypointoauth2_init,
    br_apacta_init,
    br_api2cart_init,
    br_apideck_init,
    br_apiflash_init,
    br_apifonica_init,
    br_apify_init,
    br_apilayer_init,
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
    static const br_detector *implemented[sizeof(named_factories) / sizeof(named_factories[0])];
    static bool initialized;
    if (error) *error = NULL;
    if (out) *out = NULL;
    if (count) *count = 0;
    if (!out || !count) return fail(error, "invalid detector registry outputs");
    if (!initialized) {
        /* Keep the pinned upstream defaults-list order, including disabled types. */
        for (size_t i = 0; i < sizeof(named_factories) / sizeof(named_factories[0]); ++i)
            if (named_factories[i](&implemented[i], error) != 0) return -1;
        initialized = true;
    }
    *out = implemented;
    *count = sizeof(implemented) / sizeof(implemented[0]);
    return 0;
}

bool br_detector_is_default(const br_detector *detector, const br_json *feature_flags)
{
    (void)feature_flags; /* The currently compiled providers have no feature gates. */
    if (detector && (!detector->custom_name || !detector->custom_name[0])) {
        switch (detector->type) {
        case 303: return detector->version == 1 || detector->version == 2;
        case 0: case 239: case 521: case 390: case 431: case 693: case 197: case 802:
        case 125: case 126: case 277: case 1014: case 1015: case 498: case 917: case 907:
        case 375: case 522: case 170: case 399: case 473: case 453:
        case 457: case 42: case 933: case 179: case 1032: case 632: case 212: case 458:
        case 401: case 391: case 484: case 788:
            return detector->version == 0;
        default: break;
        }
    }
    return false;
}

const char *br_detector_type_name(int32_t type)
{
    switch (type) {
    case 0: return "Alibaba";
    case 42: return "AmplitudeApiKey";
    case 125: return "AirbrakeProjectKey";
    case 126: return "AirbrakeUserKey";
    case 136: return "AdobeIO";
    case 170: return "AlgoliaAdminKey";
    case 179: return "Anypoint";
    case 197: return "Agora";
    case 212: return "ApiDeck";
    case 239: return "Abyssale";
    case 277: return "Airship";
    case 301: return "Alconost";
    case 303: return "Accuweather";
    case 375: return "Alegra";
    case 384: return "Abstract";
    case 390: return "AdafruitIO";
    case 391: return "Apify";
    case 399: return "AlienVault";
    case 401: return "Apiflash";
    case 431: return "Adzuna";
    case 453: return "Amadeus";
    case 457: return "Ambee";
    case 458: return "Api2Cart";
    case 473: return "Allsports";
    case 484: return "ApiFonica";
    case 498: return "AirVisual";
    case 521: return "AbuseIPDB";
    case 522: return "AletheiaApi";
    case 632: return "Apacta";
    case 693: return "Aeroworkflow";
    case 788: return "Apilayer";
    case 802: return "Aha";
    case 907: return "Alchemy";
    case 917: return "Aiven";
    case 933: return "Anthropic";
    case 1014: return "AirtableOAuth";
    case 1015: return "AirtablePersonalAccessToken";
    case 1032: return "AnypointOAuth2";
    default: return NULL;
    }
}
