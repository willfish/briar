/* SPDX-License-Identifier: AGPL-3.0-only */
#include "detectors.h"

#include <json-c/json.h>
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
    br_apimatic_init,
    br_apimetrics_init,
    br_apitemplate_init,
    br_apollo_init,
    br_appcues_init,
    br_appfollow_init,
    br_appointedd_init,
    br_aws_appsync_init,
    br_appsynergy_init,
    br_apptivo_init,
    br_artifactory_init,
    br_artifactoryreferencetoken_init,
    br_artsy_init,
    br_asanaoauth_init,
    br_asanapersonalaccesstoken_init,
    br_assemblyai_init,
    br_atera_init,
    br_atlassian_v1_init,
    br_atlassian_v2_init,
    br_audd_init,
    br_auth0managementapitoken_init,
    br_auth0oauth_init,
    br_autodesk_init,
    br_autoklose_init,
    br_autopilot_init,
    br_avazapersonalaccesstoken_init,
    br_aviationstack_init,
    br_aws_access_keys_init,
    br_aws_session_keys_init,
    br_axonaut_init,
    br_aylien_init,
    br_ayrshare_init,
    br_azureapimanagementsubscriptionkey_init,
    br_azure_entra_refreshtoken_init,
    br_azure_entra_serviceprincipal_v1_init,
    br_azure_entra_serviceprincipal_v2_init,
    br_azure_batch_init,
    br_azureappconfigconnectionstring_init,
    br_azure_cosmosdb_init,
    br_azurecontainerregistry_init,
    br_azuredevopspersonalaccesstoken_init,
    br_azuredirectmanagementkey_init,
    br_azurefunctionkey_init,
    br_azure_openai_init,
    br_azuresastoken_init,
    br_azuresearchadminkey_init,
    br_azuresearchquerykey_init,
    br_azure_storage_init,
    br_azureapimanagement_repositorykey_init,
    br_bannerbear_v1_init,
    br_bannerbear_v2_init,
    br_baremetrics_init,
    br_beamer_init,
    br_beebole_init,
    br_besnappy_init,
    br_besttime_init,
    br_betterstack_init,
    br_billomat_init,
    br_bitbar_init,
    br_bitbucketdatacenter_init,
    br_bitbucketapppassword_init,
    br_bitcoinaverage_init,
    br_bitfinex_init,
    br_bitlyaccesstoken_init,
    br_bitmex_init,
    br_blazemeter_init,
    br_blitapp_init,
    br_blocknative_init,
    br_blogger_init,
    br_bombbomb_init,
    br_boostnote_init,
    br_borgbase_init,
    br_box_init,
    br_boxoauth_init,
    br_braintreepayments_init,
    br_braintrust_init,
    br_brandfetch_v1_init,
    br_brandfetch_v2_init,
    br_browserstack_init,
    br_browshot_init,
    br_bscscan_init,
    br_buddyns_init,
    br_budibase_init,
    br_bugherd_init,
    br_bugsnag_init,
    br_buildkite_v1_init,
    br_buildkite_v2_init,
    br_bulbul_init,
    br_bulksms_init,
    br_buttercms_init,
    br_caflou_init,
    br_calendarific_init,
    br_calendlyapikey_init,
    br_calorieninja_init,
    br_campayn_init,
    br_cannyio_init,
    br_capsulecrm_init,
    br_captaindata_v1_init,
    br_captaindata_v2_init,
    br_carboninterface_init,
    br_cashboard_init,
    br_caspio_init,
    br_censys_init,
    br_centralstationcrm_init,
    br_confluencedatacenter_init,
    br_jiradatacenterpat_init,
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
    if (detector && (!detector->custom_name || !detector->custom_name[0])) {
        switch (detector->type) {
        case 1053: {
            if (detector->version != 0) return false;
            /* OSS main enables this flag; explicit false models package-zero
             * defaults. Accept only the exact source name and a JSON boolean. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "BraintrustDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 3: case 142: case 190: case 303: case 333: case 430: case 708: return detector->version == 1 || detector->version == 2;
        case 0: case 150: case 158: case 239: case 254: case 521: case 390: case 431: case 432: case 684: case 685: case 693: case 197: case 802:
        case 125: case 126: case 130: case 277: case 1014: case 1015: case 498: case 506: case 910: case 917: case 907:
        case 302: case 565: case 707: case 723: case 756: case 828: case 833: case 375: case 522: case 523: case 524: case 170: case 163: case 399: case 473: case 474: case 453:
        case 448: case 457: case 42: case 43: case 44: case 933: case 179: case 1032: case 632: case 212: case 458:
        case 1002: case 1003: case 401: case 391: case 484: case 485: case 788: case 637: case 647: case 648: case 1004: case 768: case 588: case 598:
        case 317: case 318: case 320: case 322: case 816: case 646: case 269: case 270: case 278: case 1042: case 181: case 385: case 387: case 388: case 389: case 800:
        case 98: case 41: case 376: case 377: case 166: case 1045: case 1047: case 1046:
        case 578: case 602: case 603: case 604: case 110: case 55: case 56: case 323: case 564: case 511: case 512: case 733: case 2: case 1052: case 959: case 947: case 953: case 957: case 971: case 1013: case 1007: case 931: case 1018: case 1019: case 1025: case 1029: case 958: case 972: case 976: case 977: case 1024: case 975:
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
    case 2: return "AWS";
    case 3: return "Azure";
    case 41: return "AsanaPersonalAccessToken";
    case 42: return "AmplitudeApiKey";
    case 43: return "BitLyAccessToken";
    case 44: return "CalendlyApiKey";
    case 55: return "Auth0oauth";
    case 56: return "Bitfinex";
    case 98: return "AsanaOauth";
    case 110: return "Auth0ManagementApiToken";
    case 125: return "AirbrakeProjectKey";
    case 126: return "AirbrakeUserKey";
    case 130: return "Calendarific";
    case 136: return "AdobeIO";
    case 142: return "Buildkite";
    case 150: return "ButterCMS";
    case 158: return "CannyIo";
    case 163: return "Ayrshare";
    case 166: return "Beamer";
    case 170: return "AlgoliaAdminKey";
    case 179: return "Anypoint";
    case 181: return "ArtifactoryAccessToken";
    case 190: return "Atlassian";
    case 197: return "Agora";
    case 212: return "ApiDeck";
    case 239: return "Abyssale";
    case 254: return "Campayn";
    case 269: return "Apptivo";
    case 270: return "CapsuleCRM";
    case 277: return "Airship";
    case 278: return "Artsy";
    case 293: return "Apollo";
    case 301: return "Alconost";
    case 302: return "Blogger";
    case 303: return "Accuweather";
    case 317: return "Bulbul";
    case 318: return "CentralStationCRM";
    case 320: return "Axonaut";
    case 322: return "Appcues";
    case 323: return "Autoklose";
    case 333: return "Brandfetch";
    case 375: return "Alegra";
    case 376: return "Audd";
    case 377: return "Baremetrics";
    case 384: return "Abstract";
    case 385: return "Billomat";
    case 387: return "Bitbar";
    case 388: return "Bugsnag";
    case 389: return "AssemblyAI";
    case 390: return "AdafruitIO";
    case 391: return "Apify";
    case 399: return "AlienVault";
    case 401: return "Apiflash";
    case 430: return "Bannerbear";
    case 431: return "Adzuna";
    case 432: return "BitcoinAverage";
    case 448: return "Browshot";
    case 453: return "Amadeus";
    case 457: return "Ambee";
    case 458: return "Api2Cart";
    case 473: return "Allsports";
    case 474: return "CalorieNinja";
    case 484: return "ApiFonica";
    case 485: return "Aylien";
    case 498: return "AirVisual";
    case 506: return "Besttime";
    case 511: return "AutoPilot";
    case 512: return "Bitmex";
    case 521: return "AbuseIPDB";
    case 522: return "AletheiaApi";
    case 523: return "BlitApp";
    case 524: return "Censys";
    case 564: return "AviationStack";
    case 565: return "BombBomb";
    case 578: return "CarbonInterface";
    case 588: return "Appfollow";
    case 598: return "BuddyNS";
    case 602: return "Bugherd";
    case 603: return "Blazemeter";
    case 604: return "Autodesk";
    case 632: return "Apacta";
    case 637: return "APIMatic";
    case 646: return "AppSynergy";
    case 647: return "Caflou";
    case 648: return "Caspio";
    case 684: return "Beebole";
    case 685: return "Cashboard";
    case 693: return "Aeroworkflow";
    case 707: return "BoostNote";
    case 708: return "CaptainData";
    case 723: return "Borgbase";
    case 733: return "AvazaPersonalAccessToken";
    case 756: return "BrowserStack";
    case 768: return "APITemplate";
    case 788: return "Apilayer";
    case 800: return "Atera";
    case 802: return "Aha";
    case 816: return "Appointedd";
    case 828: return "BraintreePayments";
    case 833: return "Bulksms";
    case 867: return "Besnappy";
    case 907: return "Alchemy";
    case 908: return "BlockNative";
    case 910: return "BscScan";
    case 917: return "Aiven";
    case 931: return "AzureStorage";
    case 933: return "Anthropic";
    case 947: return "BetterStack";
    case 953: return "Budibase";
    case 957: return "AzureBatch";
    case 958: return "AzureContainerRegistry";
    case 959: return "AWSSessionKey";
    case 971: return "AzureCosmosDBKeyIdentifiable";
    case 972: return "AzureDevopsPersonalAccessToken";
    case 973: return "AzureFunctionKey";
    case 975: return "AzureSasToken";
    case 976: return "AzureSearchAdminKey";
    case 977: return "AzureSearchQueryKey";
    case 1002: return "Box";
    case 1003: return "BoxOauth";
    case 1004: return "ApiMetrics";
    case 1007: return "AzureOpenAI";
    case 1013: return "AzureRefreshToken";
    case 1014: return "AirtableOAuth";
    case 1015: return "AirtablePersonalAccessToken";
    case 1018: return "AzureApiManagementRepositoryKey";
    case 1019: return "AzureAPIManagementSubscriptionKey";
    case 1024: return "AzureDirectManagementKey";
    case 1025: return "AzureAppConfigConnectionString";
    case 1029: return "BitbucketAppPassword";
    case 1032: return "AnypointOAuth2";
    case 1042: return "ArtifactoryReferenceToken";
    case 1045: return "BitbucketDataCenter";
    case 1046: return "JiraDataCenterPAT";
    case 1047: return "ConfluenceDataCenter";
    case 1052: return "AWSAppSync";
    case 1053: return "BrainTrustApiKey";
    default: return NULL;
    }
}
