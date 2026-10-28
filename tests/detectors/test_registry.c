/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"

typedef struct {
    int32_t type, version;
    const char *name, *keyword;
    size_t key_len;
    bool enabled;
    int64_t span;
} registration;

static const registration expected[] = {
    {239, 0, "Abyssale", "abyssale", 40, true, -1},
    {384, 0, "Abstract", "abstract", 32, false, -1},
    {521, 0, "AbuseIPDB", "abuseipdb", 80, true, -1},
    {303, 1, "Accuweather", "accuweather", 35, true, -1},
    {303, 2, "Accuweather", "accuweather", 32, true, -1},
    {390, 0, "AdafruitIO", "aio_", 32, true, -1},
    {136, 0, "AdobeIO", "adobe", 32, false, 1024},
    {431, 0, "Adzuna", "adzuna", 32, true, 1024},
    {693, 0, "Aeroworkflow", "aeroworkflow", 20, true, 1024},
    {197, 0, "Agora", "agora", 32, true, 1024},
    {802, 0, "Aha", "aha.io", 64, true, 1024},
    {125, 0, "AirbrakeProjectKey", "airbrake", 32, true, 1024},
    {126, 0, "AirbrakeUserKey", "airbrake", 40, true, -1},
    {277, 0, "Airship", "airship", 91, true, -1},
    {1014, 0, "AirtableOAuth", "airtable", sizeof("Native7.v1.Synthetic_-Payload.1a2b3c") - 1, true, -1},
    {1015, 0, "AirtablePersonalAccessToken", "airtable", 82, true, -1},
    {498, 0, "AirVisual", "airvisual", 36, true, -1},
    {917, 0, "Aiven", "aiven", 372, true, -1},
    {907, 0, "Alchemy", "alchemy", 32, true, -1},
    {301, 0, "Alconost", "alconost", 32, false, -1},
    {375, 0, "Alegra", "alegra", 20, true, -1},
    {522, 0, "AletheiaApi", "aletheiaapi", 32, true, -1},
    {170, 0, "AlgoliaAdminKey", "algolia", 32, true, 1024},
    {0, 0, "Alibaba", "LTAI", 30, true, 1024},
    {399, 0, "AlienVault", "alienvault", 64, true, -1},
    {473, 0, "Allsports", "allsports", 64, true, -1},
    {453, 0, "Amadeus", "amadeus", 32, true, 1024},
    {457, 0, "Ambee", "ambee", 64, true, -1},
    {42, 0, "AmplitudeApiKey", "amplitude", 32, true, 1024},
    {933, 0, "Anthropic", "sk-ant-api03", 108, true, -1},
    {179, 0, "Anypoint", "anypoint", 36, true, 1024},
    {1032, 0, "AnypointOAuth2", "anypoint", 32, true, 1024},
    {632, 0, "Apacta", "apacta", 36, true, -1},
    {458, 0, "Api2Cart", "api2cart", 32, true, -1},
    {212, 0, "ApiDeck", "apideck", 101, true, 1024},
    {401, 0, "Apiflash", "apiflash", 32, true, 1024},
    {484, 0, "ApiFonica", "apifonica", 39, true, -1},
    {391, 0, "Apify", "apify", 46, true, -1},
    {788, 0, "Apilayer", "apilayer", 32, true, -1},
    {637, 0, "APIMatic", "apimatic", 64, true, 1024},
    {1004, 0, "ApiMetrics", "apimetrics", 32, true, -1},
    {768, 0, "APITemplate", "apitemplate", 39, true, -1},
    {293, 0, "Apollo", "apollo", 22, false, -1},
    {322, 0, "Appcues", "appcues", 36, true, 1024},
    {588, 0, "Appfollow", "appfollow", 155, true, -1},
    {816, 0, "Appointedd", "appointedd", 88, true, -1},
    {1052, 0, "AWSAppSync", "da2-", 30, true, 1024},
    {646, 0, "AppSynergy", "appsynergy", 64, true, -1},
    {269, 0, "Apptivo", "apptivo", 36, true, 1024},
    {181, 0, "ArtifactoryAccessToken", "artifactory", 73, true, 1024},
    {1042, 0, "ArtifactoryReferenceToken", "cmVmdGtu", 64, true, 1024},
    {278, 0, "Artsy", "artsy", 32, true, 1024},
    {98, 0, "AsanaOauth", "asana", 51, true, -1},
    {41, 0, "AsanaPersonalAccessToken", "asana", 51, true, -1},
    {389, 0, "AssemblyAI", "assemblyai", 32, true, -1},
    {800, 0, "Atera", "atera", 32, true, -1},
    {190, 1, "Atlassian", "atlassian", 24, true, -1},
    {190, 2, "Atlassian", "ATCTT3xFfG", 43, true, -1},
    {376, 0, "Audd", "audd", 32, true, -1},
    {110, 0, "Auth0ManagementApiToken", "auth0", 2000, true, 1024},
    {55, 0, "Auth0oauth", "auth0", 64, true, 1024},
    {604, 0, "Autodesk", "autodesk", 32, true, 1024},
    {323, 0, "Autoklose", "autoklose", 32, true, -1},
    {511, 0, "AutoPilot", "autopilot", 32, true, -1},
    {733, 0, "AvazaPersonalAccessToken", "avaza", 45, true, -1},
    {564, 0, "AviationStack", "aviationstack", 32, true, -1},
    {2, 0, "AWS", "AKIA", 20, true, 1024},
    {959, 0, "AWSSessionKey", "ASIA", 20, true, 2048},
    {320, 0, "Axonaut", "axonaut", 32, true, -1},
    {485, 0, "Aylien", "aylien", 32, true, 1024},
    {163, 0, "Ayrshare", "ayrshare", 35, true, -1},
    {1019, 0, "AzureAPIManagementSubscriptionKey", ".azure-api.net", sizeof("https://briar-api.azure-api.net") - 1, true, 1024},
    {1013, 0, "AzureRefreshToken", "0.A", 366, true, 1024},
    {3, 1, "Azure", "azure", 32, true, 1024},
    {3, 2, "Azure", "q~", 37, true, 1024},
    {957, 0, "AzureBatch", ".batch.azure.com", sizeof("https://briar.region.batch.azure.com") - 1, true, 1024},
    {1025, 0, "AzureAppConfigConnectionString", ".azconfig.io", 32, true, 1024},
    {971, 0, "AzureCosmosDBKeyIdentifiable", ".documents.azure.com", 88, true, -1},
    {958, 0, "AzureContainerRegistry", ".azurecr.io", 52, true, 1024},
    {972, 0, "AzureDevopsPersonalAccessToken", "azure", 52, true, 1024},
    {1024, 0, "AzureDirectManagementKey", ".management.azure-api.net", sizeof("https://briar-direct.management.azure-api.net") - 1, true, 1024},
    {973, 0, "AzureFunctionKey", "azure", 32, false, 1024},
    {1007, 0, "AzureOpenAI", ".openai.azure.com", 32, true, -1},
    {975, 0, "AzureSasToken", "azure", sizeof("https://briar-store.blob.core.windows.net/container") - 1, true, 1024},
    {976, 0, "AzureSearchAdminKey", "azure", 52, true, 1024},
    {977, 0, "AzureSearchQueryKey", "azure", 52, true, 1024},
    {931, 0, "AzureStorage", "DefaultEndpointsProtocol=http", 88, true, 1024},
    {1018, 0, "AzureApiManagementRepositoryKey", "azure", 105, true, 1024},
    {430, 1, "Bannerbear", "bannerbear", 24, true, -1},
    {430, 2, "Bannerbear", "bb_pr_", 36, true, -1},
    {377, 0, "Baremetrics", "baremetrics", 21, true, -1},
    {166, 0, "Beamer", "beamer", 46, true, -1},
    {684, 0, "Beebole", "beebole", 40, true, -1},
    {867, 0, "Besnappy", "besnappy", 64, false, -1},
    {506, 0, "Besttime", "besttime", 36, true, -1},
    {947, 0, "BetterStack", "betterstack", 24, true, -1},
    {385, 0, "Billomat", "billomat", 32, true, 1024},
    {387, 0, "Bitbar", "bitbar", 32, true, -1},
    {1045, 0, "BitbucketDataCenter", "BBDC-", 45, true, 1024},
    {1029, 0, "BitbucketAppPassword", "bitbucket", 43, true, -1},
    {432, 0, "BitcoinAverage", "bitcoinaverage", 43, true, -1},
    {56, 0, "Bitfinex", "bitfinex", 43, true, 1024},
    {43, 0, "BitLyAccessToken", "bitly", 40, true, -1},
    {512, 0, "Bitmex", "bitmex", 48, true, 1024},
    {603, 0, "Blazemeter", "blazemeter", 36, true, -1},
    {523, 0, "BlitApp", "blitapp", 39, true, -1},
    {908, 0, "BlockNative", "blocknative", 36, false, -1},
    {302, 0, "Blogger", "blogger", 39, true, -1},
    {565, 0, "BombBomb", "bombbomb", 39, true, -1},
    {707, 0, "BoostNote", "boostnote", 64, true, -1},
    {723, 0, "Borgbase", "borgbase", 150, true, -1},
    {1002, 0, "Box", "box", 32, true, -1},
    {1003, 0, "BoxOauth", "box", 32, true, -1},
    {828, 0, "BraintreePayments", "braintree", 32, true, 1024},
    {1053, 0, "BrainTrustApiKey", "braintrust", 51, true, -1},
    {333, 1, "Brandfetch", "brandfetch", 40, true, -1},
    {333, 2, "Brandfetch", "brandfetch", 44, true, -1},
    {756, 0, "BrowserStack", "browserstack", 20, true, 1024},
    {448, 0, "Browshot", "browshot", 28, true, -1},
    {910, 0, "BscScan", "bscscan", 34, true, -1},
    {598, 0, "BuddyNS", "buddyns", 40, true, -1},
    {953, 0, "Budibase", "budibase", 113, true, -1},
    {602, 0, "Bugherd", "bugherd", 22, true, -1},
    {388, 0, "Bugsnag", "bugsnag", 36, true, -1},
    {142, 1, "Buildkite", "buildkite", 40, true, -1},
    {142, 2, "Buildkite", "bkua_", 45, true, -1},
    {317, 0, "Bulbul", "bulbul", 32, true, -1},
    {833, 0, "Bulksms", "bulksms", 29, true, 1024},
    {150, 0, "ButterCMS", "buttercms", 40, true, -1},
    {647, 0, "Caflou", "caflou", 155, true, -1},
    {130, 0, "Calendarific", "calendarific", 32, true, -1},
    {44, 0, "CalendlyApiKey", "calendly", 209, true, -1},
    {474, 0, "CalorieNinja", "calorieninja", 40, true, -1},
    {254, 0, "Campayn", "campayn", 64, true, -1},
    {158, 0, "CannyIo", "canny", 36, true, -1},
    {270, 0, "CapsuleCRM", "capsulecrm", 64, true, -1},
    {708, 1, "CaptainData", "captaindata", 64, true, 1024},
    {708, 2, "CaptainData", "captaindata", 64, true, -1},
    {578, 0, "CarbonInterface", "carboninterface", 21, true, -1},
    {685, 0, "Cashboard", "cashboard", 15, true, 1024},
    {648, 0, "Caspio", "caspio", 50, true, 1024},
    {524, 0, "Censys", "censys", 32, true, 1024},
    {318, 0, "CentralStationCRM", "centralstationcrm", 30, true, -1},
    {739, 0, "CexIO", "cexio", 24, true, 1024},
    {815, 0, "Chartmogul", "chartmogul", 32, true, -1},
    {208, 0, "Chatbot", "chatbot", 32, true, -1},
    {692, 0, "Chatfule", "chatfuel", 128, true, -1},
    {643, 0, "ChecIO", "checio", 48, true, -1},
    {649, 0, "ChecklyHQ", "checklyhq", 32, true, -1},
    {187, 0, "Checkout", "checkout", 39, true, 1024},
    {709, 0, "Checkvist", "checkvist", 14, true, 1024},
    {477, 0, "Cicero", "cicero", 40, true, -1},
    {4, 1, "Circle", "circle", 40, true, -1},
    {4, 2, "Circle", "CCIPAT_", 70, true, -1},
    {57, 0, "Clarifai", "clarifai", 32, true, -1},
    {334, 0, "Clearbit", "clearbit", 35, true, -1},
    {456, 0, "ClickHelp", "clickhelp.co", 19, true, 1024},
    {209, 0, "ClickSendsms", "clicksendsms", 36, true, 1024},
    {366, 0, "ClickupPersonalToken", "clickup", 43, true, -1},
    {710, 0, "Cliengo", "cliengo", 36, true, -1},
    {307, 0, "Clientary", "ronin", 26, true, 1024},
    {255, 0, "Clinchpad", "clinchpad", 32, true, -1},
    {280, 0, "Clockify", "clockify", 48, true, -1},
    {189, 0, "ClockworkSMS", "clockworksms", 5, true, 1024},
    {215, 0, "Close", "close", 49, true, -1},
    {829, 0, "CloudConvert", "cloudconvert", 836, true, -1},
    {650, 0, "CloudElements", "cloudelements", 43, true, 1024},
    {100, 1, "CloudflareApiToken", "cloudflare", 40, true, -1},
    {100, 2, "CloudflareApiToken", "cfut_", 53, true, 1024},
    {59, 0, "CloudflareCaKey", "cloudflare", 176, true, -1},
    {58, 1, "CloudflareGlobalApiKey", "cloudflare", 37, true, 1024},
    {58, 2, "CloudflareGlobalApiKey", "cfk_", 52, true, 1024},
    {721, 0, "CloudImage", "cloudimage", 30, true, -1},
    {1048, 0, "Cloudinary", "cloudinary", 15, true, 1024},
    {358, 0, "Cloudmersive", "cloudmersive", 36, true, -1},
    {324, 0, "Cloudplan", "cloudplan", 32, true, -1},
    {805, 0, "Cloudsmith", "cloudsmith", 40, true, -1},
    {525, 0, "Cloverly", "cloverly", 28, true, -1},
    {711, 0, "Cloze", "cloze", 32, true, 1024},
    {513, 0, "ClustDoc", "clustdoc", 60, true, -1},
    {960, 0, "Coda", "coda", 36, true, -1},
    {185, 0, "Codacy", "codacy", 20, true, -1},
    {844, 0, "Codeclimate", "codeclimate", 40, true, -1},
    {845, 0, "Codemagic", "codemagic", 43, true, -1},
    {783, 0, "Codequiry", "codequiry", 64, true, -1},
    {554, 0, "CoinApi", "coinapi", 36, true, -1},
    {5, 0, "Coinbase", "begin ec", 88, true, -1},
    {402, 0, "Coinlayer", "coinlayer", 32, true, -1},
    {378, 0, "Coinlib", "coinlib", 16, true, -1},
    {823, 0, "Collect2", "collect2", 36, true, -1},
    {749, 0, "Column", "column", 32, true, -1},
    {433, 0, "CommerceJS", "commercejs", 48, true, -1},
    {566, 0, "Commodities", "commodities", 60, true, -1},
    {256, 0, "CompanyHub", "companyhub", 20, true, 1024},
    {1047, 0, "ConfluenceDataCenter", "confluence", 44, true, 1024},
    {60, 0, "Confluent", "confluent", 16, true, 1024},
    {103, 0, "ContentfulPersonalAccessToken", "CFPAT-", 49, true, -1},
    {769, 0, "ConversionTools", "conversiontools", 159, true, -1},
    {831, 0, "ConvertApi", "convertapi", 23, true, -1},
    {225, 0, "Convertkit", "convertkit", 22, true, -1},
    {664, 0, "Convier", "convier", 43, true, -1},
    {214, 0, "Copper", "copper", 32, true, 1024},
    {920, 0, "Couchbase", "couchbase://", 50, true, 1024},
    {526, 0, "CountryLayer", "countrylayer", 32, true, -1},
    {665, 0, "Courier", "courier", 33, true, -1},
    {192, 0, "Coveralls", "coveralls", 37, true, -1},
    {770, 0, "CraftMyPDF", "craftmypdf", 35, true, -1},
    {335, 0, "Crowdin", "crowdin", 80, true, -1},
    {393, 0, "CryptoCompare", "cryptocompare", 64, true, -1},
    {382, 0, "CurrencyCloud", "currencycloud", 64, true, 1024},
    {499, 0, "Currencyfreaks", "currencyfreaks", 32, true, -1},
    {354, 0, "Currencylayer", "currencylayer", 32, true, -1},
    {380, 0, "CurrencyScoop", "currencyscoop", 32, true, -1},
    {403, 0, "CurrentsAPI", "currentsapi", 48, true, -1},
    {226, 0, "CustomerGuru", "customerguru", 30, true, 1024},
    {211, 0, "CustomerIO", "customerio", 20, true, 1024},
    {138, 0, "D7Network", "d7network", 24, true, -1},
    {585, 0, "DailyCO", "daily", 64, false, -1},
    {619, 0, "Dandelion", "dandelion", 32, true, -1},
    {762, 0, "Dareboost", "dareboost", 60, true, -1},
    {834, 0, "Databox", "databox", 21, true, -1},
    {62, 0, "DatabricksToken", "databricks", 36, true, 1024},
    {1043, 0, "DatadogApikey", "datadog", 32, true, 1024},
    {39, 0, "DatadogToken", "datadog", 40, true, 1024},
    {404, 0, "DataGov", "data.gov", 40, true, -1},
    {257, 0, "Debounce", "debounce", 13, false, -1},
    {621, 0, "DeepAI", "deepai", 36, true, -1},
    {418, 0, "Deepgram", "deepgram", 40, true, -1},
    {1026, 0, "DeepSeek", "deepseek", 35, true, -1},
    {237, 0, "Delighted", "delighted", 32, true, -1},
    {863, 0, "Demio", "demio", 32, true, 1024},
    {954, 0, "DenoDeploy", "ddp_", 40, true, -1},
    {683, 0, "Deputy", "deputy", 32, true, 1024},
    {794, 0, "Detectify", "detectify", 32, true, -1},
    {434, 0, "DetectLanguage", "detectlanguage", 32, true, -1},
    {567, 0, "Dfuse", "dfuse", 36, true, -1},
    {726, 0, "Diffbot", "diffbot", 32, true, -1},
    {819, 0, "Diggernaut", "diggernaut", 40, true, -1},
    {64, 0, "DigitalOceanToken", "digitalocean", 64, true, -1},
    {897, 0, "DigitalOceanV2", "dop_v1_", 71, true, -1},
    {65, 0, "DiscordBotToken", "discord", 59, true, 1024},
    {66, 0, "DiscordWebhook", "https://discord.com/api/webhooks/", 120, true, -1},
    {789, 0, "Disqus", "disqus", 64, true, -1},
    {666, 0, "Ditto", "ditto", 77, true, -1},
    {281, 0, "Dnscheck", "dnscheck", 32, true, 1024},
    {343, 0, "Docker", "\"auths\"", 4, true, -1},
    {921, 1, "Dockerhub", "docker", 36, true, 1024},
    {921, 2, "Dockerhub", "docker", 36, true, 1024},
    {838, 0, "Docparser", "docparser", 40, true, -1},
    {311, 0, "Documo", "documo", 237, true, -1},
    {919, 0, "Docusign", "docusign", 36, true, 1024},
    {196, 0, "Doppler", "dp.ct.", 46, true, -1},
    {325, 0, "Dotdigital", "@apiconnector.com", 37, true, 1024},
    {386, 0, "Dovico", "dovico", 34, true, 1024},
    {651, 0, "DronaHQ", "dronahq", 50, true, -1},
    {135, 0, "DroneCI", "droneci", 32, true, -1},
    {18, 0, "Dropbox", "dropbox", 133, true, -1},
    {1059, 0, "DuffelToken", "duffel_test_", 55, true, -1},
    {1063, 0, "Duo", "duosecurity", 20, true, 1024},
    {821, 0, "Duply", "duply", 36, true, 1024},
    {180, 0, "Dwolla", "dwolla", 50, true, 1024},
    {359, 0, "Dynalist", "dynalist", 128, true, -1},
    {258, 0, "Dyspatch", "dyspatch", 52, true, -1},
    {639, 0, "EagleEyeNetworks", "eagleeyenetworks", 15, true, 1024},
    {282, 0, "EasyInsight", "easyinsight", 20, true, 1024},
    {801, 0, "EcoStruxureIT", "ecostruxureit", 58, true, -1},
    {424, 0, "Edamam", "edamam", 32, true, 1024},
    {568, 0, "EdenAI", "edenai", 173, true, -1},
    {1046, 0, "JiraDataCenterPAT", "jira", 44, true, 1024},
};

/* Registration must dispatch real initialized scanners, not metadata stubs. */
static void check_dispatch(const br_detector *detector, const registration *entry)
{
    if (entry->type == 1063) {
        static const char host[] = "api-offline.duosecurity.com", ikey[] = "DI0123456789ABCDEFGH";
        static const char skey[] = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTt";
        static const char input[] = "api-offline.duosecurity.com\nduo DI0123456789ABCDEFGH\nduo AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTt";
        static const char raw_v2[] = "api-offline.duosecurity.com:DI0123456789ABCDEFGH:AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTt";
        br_results results = test_scan(detector, NULL, false, input, sizeof(input) - 1);
        CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 1063 && result->raw.len == entry->key_len);
        CHECK(result->raw.len == sizeof(ikey) - 1 && !memcmp(result->raw.data, ikey, sizeof(ikey) - 1));
        CHECK(result->raw_v2.len == sizeof(raw_v2) - 1 && !memcmp(result->raw_v2.data, raw_v2, sizeof(raw_v2) - 1));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->structured_data && !result->verification_from_cache);
        CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set);
        CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 4);
        const char *names[] = {"host", "ikey", "skey", "application"};
        const char *values[] = {host, ikey, skey, "Admin API"};
        br_json *part = NULL;
        for (size_t i = 0; i < 4; ++i) {
            CHECK(json_object_object_get_ex(result->secret_parts, names[i], &part));
            CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), values[i]));
        }
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "application", &part) && !strcmp(json_object_get_string(part), "Admin API"));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 343) {
        static const char input[] = "{\"auths\":{\"reg.invalid\":{\"auth\":\"dTo=\"}}}";
        static const char raw_v2[] = "{\"registry\":\"reg.invalid\",\"auth\":\"dTo=\"}";
        br_scan_ctx ctx = {0}; /* Source AddLogger requires a nonnil context even without verification. */
        br_results results = test_scan(detector, &ctx, false, input, sizeof(input) - 1);
        CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 343 && result->raw.len == entry->key_len);
        CHECK(result->raw.len == 4 && !memcmp(result->raw.data, "dTo=", 4));
        CHECK(result->raw_v2.len == sizeof(raw_v2) - 1 && !memcmp(result->raw_v2.data, raw_v2, sizeof(raw_v2) - 1));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->structured_data);
        CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set);
        br_json *part = NULL;
        CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "registry", &part) && !strcmp(json_object_get_string(part), "reg.invalid"));
        CHECK(json_object_object_get_ex(result->secret_parts, "auth", &part) && !strcmp(json_object_get_string(part), "dTo="));
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "Username", &part) && !strcmp(json_object_get_string(part), "u"));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 920) {
        static const char input[] = "couchbase://cb.a1.cloud.couchbase.com\nuser:briar7\npass:aB7!\n";
        static const char raw[] = "briar7:aB7!@couchbases://cb.a1.cloud.couchbase.com";
        const char *names[] = {"host", "username", "password"};
        const char *values[] = {"couchbases://cb.a1.cloud.couchbase.com", "briar7", "aB7!"};
        br_results results = test_scan(detector, NULL, false, input, sizeof(input) - 1);
        CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 920 && result->raw.len == entry->key_len);
        CHECK(result->raw.len == sizeof(raw) - 1 && !memcmp(result->raw.data, raw, sizeof(raw) - 1));
        CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->redacted && !result->extra_data);
        CHECK(!result->verified && !result->verification_error && !result->primary_secret.data && !result->primary_secret.len);
        CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
        for (size_t i = 0; i < 3; ++i) {
            br_json *part = NULL;
            CHECK(json_object_object_get_ex(result->secret_parts, names[i], &part));
            CHECK(json_object_is_type(part, json_type_string) && !strcmp(json_object_get_string(part), values[i]));
        }
        br_results_clear(&results);
        return;
    }
    char key[5001], secondary_buffer[89], session_buffer[133], input[8192];
    static const char cloudinary_secret[] = "AbCd0123EfGh4567IjKl8901MnO";
    test_secret(key, entry->key_len, 0);
    if (entry->type == 163) strcpy(key, "B7C9D2E5-F6G8H3J4-K1M0N2P4-Q6R8S1T3");
    if (entry->type == 3 && entry->version == 2) memcpy(key, "b7c1Q~", 6);
    if (entry->type == 1018) {
        memcpy(key, "git&000000000007&", 17);
        key[103] = key[104] = '=';
    }
    if (entry->type == 1013) {
        memcpy(key, "0.A", 3);
        test_secret(key + 3, 60, 11);
        memcpy(key + 63, ".Ag", 3);
        test_secret(key + 66, 300, 23);
    }
    if (entry->type == 41) {
        static const char prefix[] = "0/1234567890123456:";
        memcpy(key, prefix, sizeof(prefix) - 1);
    }
    if (entry->type == 190 && entry->version == 2) {
        memcpy(key, "ATCTT3xFfG", 10);
        key[34] = '=';
    }
    if (entry->type == 303 && entry->version == 1) key[7] = '%';
    if (entry->type == 44) {
        memcpy(key, "eyJ", 3); key[103] = '.';
        memcpy(key + 104, "eyJ", 3); key[207] = '.'; key[208] = 'Z';
    }
    if (entry->type == 664) memcpy(key, "07|", 3);
    if (entry->type == 138) key[23] = '=';
    if (entry->type == 665) memcpy(key, "pk_Z_", 5);
    if (entry->type == 65) key[24] = key[31] = '.';
    if (entry->type == 311) {
        key[0] = key[37] = 'e'; key[1] = key[38] = 'y';
        key[36] = key[193] = '.';
    }
    if (entry->type == 921) {
        if (entry->version == 1) key[8] = key[13] = key[18] = key[23] = '-';
        else memcpy(key, "dckr_pat_", 9);
    }
    if (entry->type == 666) {
        key[8] = key[13] = key[18] = key[23] = '-';
        key[36] = '.';
    }
    if (entry->type == 567) memcpy(key, "web_", 4);
    if (entry->type == 196) memcpy(key, "dp.ct.", 6);
    if (entry->type == 18) memcpy(key, "sl.", 3);
    if (entry->type == 1059) memcpy(key, "duffel_test_", 12);
    if (entry->type == 386) key[32] = '.';
    if (entry->type == 359) { key[45] = '-'; key[88] = '_'; }
    if (entry->type == 801) { memcpy(key, "AK1", 3); key[20] = '/'; }
    if (entry->type == 568) { key[36] = key[129] = '.'; key[172] = '_'; }
    if (entry->type == 258)
        for (size_t i = 0; i < entry->key_len; ++i)
            if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
    if (entry->type == 325) strcpy(key, "apiuser-a1b2c3d4e5f6@apiconnector.com");
    if (entry->type == 919 || entry->type == 821) {
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[8] = key[13] = key[18] = key[23] = '-';
    }
    if (entry->type == 66) {
        char secret[69]; test_secret(secret, 68, 11);
        snprintf(key, sizeof(key), "https://discord.com/api/webhooks/123456789012345678/%s", secret);
    }
    if (entry->type == 838)
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
    if (entry->type == 897) {
        memcpy(key, "dop_v1_", 7);
        for (size_t i = 7; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
    }
    if (entry->type == 225) key[5] = '_';
    if (entry->type == 831) memcpy(key, "secret_", 7);
    if (entry->type == 103) memcpy(key, "CFPAT-", 6);
    if (entry->type == 769) { memcpy(key, "ey", 2); key[10] = '.'; key[20] = '_'; }
    if (entry->type == 110) memcpy(key, "ey", 2);
    if (entry->type == 647) memcpy(key, "eyJhbGciOiJIUzI1NiJ9", 20);
    if (entry->type == 430 && entry->version == 1) key[22] = key[23] = 't';
    if (entry->type == 430 && entry->version == 2) {
        memcpy(key, "bb_pr_", 6);
        for (size_t i = 6; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
    }
    if (entry->type == 158 || entry->type == 388 || entry->type == 603) key[8] = key[13] = key[18] = key[23] = '-';
    if (entry->type == 1029) memcpy(key, "briar7:ATBB", 11);
    if (entry->type == 166) key[45] = '=';
    if (entry->type == 377) memcpy(key, "sk_", 3);
    if (entry->type == 390) memcpy(key, "aio_", 4);
    if (entry->type == 391) memcpy(key, "apify_api_", 10);
    if (entry->type == 181) memcpy(key, "AKCp", 4);
    if (entry->type == 1042) memcpy(key, "cmVmdGtu", 8);
    if (entry->type == 1045) memcpy(key, "BBDC-", 5);
    if (entry->type == 1052) memcpy(key, "da2-", 4);
    if (entry->type == 1047 || entry->type == 1046) strcpy(key, "MTIzNDU2Nzg5MDEyOmFiY2RlZmdoaWprbG1ub3BxcnN0");
    if (entry->type == 484) strcpy(key, "b7c9d2e5f6g-h3j4-k1m0-n2p4-q6r8s1t3u5v7");
    if (entry->type == 588) {
        static const char header[] = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.";
        memcpy(key, header, sizeof(header) - 1);
        key[sizeof(header) - 1 + 74] = '.';
    }
    const char *secondary = NULL, *secondary_name = NULL, *session = NULL;
    switch (entry->type) {
    case 959:
        strcpy(key, "ASIAQWERTYUIOPASDFGH");
        secondary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";
        secondary_name = "secret_access_key";
        memcpy(session_buffer, "YXdz", 4);
        for (size_t i = 4; i < sizeof(session_buffer) - 1; ++i)
            session_buffer[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(i - 4) % 64];
        session_buffer[sizeof(session_buffer) - 1] = '\0';
        session = session_buffer;
        break;
    case 2:
        strcpy(key, "AKIAQWERTYUIOPASDFGH");
        secondary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN";
        secondary_name = "secret_access_key";
        break;
    case 975:
        strcpy(key, "https://briar-store.blob.core.windows.net/container");
        secondary = "sp=r&sv=2025-01-01&sr=c&se=2027-01-01T00:00:00Z&sig=AbCdEf0123456789%3D";
        secondary_name = "key";
        break;
    case 973:
        secondary = "https://briar-functions.azurewebsites.net/api/Run-Task";
        secondary_name = "url";
        break;
    case 1024:
        strcpy(key, "https://briar-direct.management.azure-api.net");
        test_secret(secondary_buffer, 86, 7);
        memcpy(secondary_buffer + 86, "==", 3);
        secondary = secondary_buffer;
        secondary_name = "key";
        break;
    case 977:
        secondary = "https://briarsearch.search.windows.net/indexes/briarindex";
        secondary_name = "url";
        break;
    case 976:
        secondary = "BriarSearch7";
        secondary_name = "service";
        break;
    case 954:
        memcpy(key, "ddp_", 4);
        break;
    case 1026:
        memcpy(key, "sk-", 3);
        /* The token suffix is lowercase alphanumeric, not hex-only. */
        for (size_t i = 3; i < entry->key_len; ++i)
            if (key[i] >= 'A' && key[i] <= 'Z') key[i] += 'a' - 'A';
        break;
    case 972:
        for (size_t i = 0; i < entry->key_len; ++i)
            if (key[i] >= 'A' && key[i] <= 'Z') key[i] += 'a' - 'A';
        secondary = "Briar-Org7";
        secondary_name = "organization";
        break;
    case 958:
        memcpy(key + 42, "+ACR", 4);
        secondary = "briar-registry";
        secondary_name = "username";
        break;
    case 1025:
        secondary = "https://briar-config.azconfig.io";
        secondary_name = "endpoint";
        break;
    case 1019:
        strcpy(key, "https://briar-api.azure-api.net");
        test_secret(secondary_buffer, 32, 7);
        secondary_buffer[7] = '-';
        secondary = secondary_buffer;
        secondary_name = "key";
        break;
    case 1018:
        secondary = "briar-apim.scm.azure-api.net";
        secondary_name = "url";
        break;
    case 931:
        secondary = "briarstorage";
        secondary_name = "account_name";
        break;
    case 971:
        key[86] = key[87] = '=';
        secondary = "briar-cosmos.documents.azure.com";
        secondary_name = "account_url";
        break;
    case 957:
        strcpy(key, "https://briar.region.batch.azure.com");
        test_secret(secondary_buffer, 88, 7);
        secondary = secondary_buffer;
        secondary_name = "account_key";
        break;
    case 1052:
        secondary = "https://abcdefghijklmnopqrstuvwx12.appsync-api.us-east-1.amazonaws.com/graphql";
        secondary_name = "endpoint";
        break;
    case 0: secondary = "LTAIB7c9D2e5F6g8H3j4K"; secondary_name = "id"; break;
    case 42:
        for (size_t i = 0; i < 32; ++i) {
            key[i] = "0123456789abcdef"[i % 16];
            secondary_buffer[i] = "0123456789abcdef"[(i + 5) % 16];
        }
        secondary_buffer[32] = '\0';
        secondary = secondary_buffer;
        secondary_name = "secret";
        break;
    case 55:
        test_secret(secondary_buffer, 32, 11);
        secondary = secondary_buffer;
        secondary_name = "client_id";
        break;
    case 110: secondary = "fixture-tenant.us.auth0.com"; secondary_name = "domain"; break;
    case 65: secondary = "12345678901234567"; secondary_name = "id"; break;
    case 281: secondary = "G7h9K2m4-N6p8-Q1r3-S5t7-U9v1W3x5Y7z9"; secondary_name = "id"; break;
    case 921: secondary = "briar7"; secondary_name = "username"; break;
    case 325: secondary = "AbCd1234"; secondary_name = "password"; break;
    case 639: secondary = "u7b9r@m4c8p.k2"; secondary_name = "email"; break;
    case 424: secondary = "z7m9q2r4"; secondary_name = "id"; break;
    case 821: secondary = "AB7CD9E-F2G4H6J-K8L1M3N-P5Q7R9S"; secondary_name = "id"; break;
    case 282:
        memcpy(secondary_buffer, key, entry->key_len + 1);
        secondary_buffer[0] = key[0] == 'Z' ? 'Y' : 'Z';
        secondary = secondary_buffer; secondary_name = "id";
        break;
    case 180:
        memcpy(secondary_buffer, key, entry->key_len + 1);
        secondary_buffer[0] = key[0] == 'Z' ? 'Y' : 'Z';
        secondary = secondary_buffer; secondary_name = "secret";
        break;
    case 386:
        memcpy(secondary_buffer, key, entry->key_len + 1);
        secondary_buffer[33] = key[33] == 'q' ? 'z' : 'q';
        secondary = secondary_buffer; secondary_name = "user_key";
        break;
    case 919: secondary = "a2b4c6d8-e0f1-2345-6789-abcdf0123456"; secondary_name = "secret"; break;
    case 125: secondary = "004207"; secondary_name = "id"; break;
    case 136: secondary = "C7d8E9f0.G1H"; secondary_name = "id"; break;
    case 170: secondary = "B7C9D2E5F6"; secondary_name = "id"; break;
    case 179:
        strcpy(key, "b7c9d2e5-f6g8-h3j4-k1m0-n2p4q6r8s1t3");
        secondary = "c7d8e9f0-g1h2-i3j4-k5l6-m7n8o9p0q1r2";
        secondary_name = "organization";
        break;
    case 269:
        test_secret(secondary_buffer, 32, 17);
        secondary = secondary_buffer;
        secondary_name = "id";
        break;
    case 278:
        test_secret(secondary_buffer, 20, 17);
        secondary = secondary_buffer;
        secondary_name = "id";
        break;
    case 322:
        test_secret(secondary_buffer, 39, 17);
        secondary = secondary_buffer;
        secondary_name = "username";
        break;
    case 385:
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        secondary = "briar7";
        secondary_name = "id";
        break;
    case 375: secondary = "fixture@example.test"; secondary_name = "id"; break;
    case 431:
    case 485: secondary = "c7d8e9f0"; secondary_name = "id"; break;
    case 453: secondary = "B7c9D2e5F6g8H3j4"; secondary_name = "secret"; break;
    case 693: secondary = "00042"; secondary_name = "id"; break;
    case 604:
        test_secret(secondary_buffer, 16, 11);
        secondary = secondary_buffer;
        secondary_name = "secret";
        break;
    case 197:
        test_secret(secondary_buffer, 32, 11);
        secondary = secondary_buffer;
        secondary_name = "secret";
        break;
    case 802:
        for (size_t i = 0; i < 64; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[64] = '\0';
        secondary = "synthetic.aha.io";
        secondary_name = "url";
        break;
    case 214:
        secondary = "briar7@FiXtUrE.test";
        secondary_name = "id";
        break;
    case 256:
        secondary = key; /* The key also matches the ID grammar: retain its self-pair. */
        secondary_name = "id";
        break;
    case 60:
        test_secret(secondary_buffer, 64, 11);
        secondary = secondary_buffer;
        secondary_name = "secret";
        break;
    case 56:
        test_secret(secondary_buffer, 43, 13);
        secondary = secondary_buffer;
        break;
    case 756:
        secondary = "briaruser17";
        secondary_name = "username";
        break;
    case 142:
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        if (entry->version == 2) memcpy(key, "bkua_", 5);
        break;
    case 333:
        if (entry->version == 2) key[43] = '=';
        break;
    case 1053:
        memcpy(key, "sk-", 3);
        break;
    case 4:
        if (entry->version == 1) {
            for (size_t i = 0; i < 40; ++i) key[i] = "0123456789aBcDeF"[i % 16];
        } else {
            memcpy(key, "CCIPAT_", 7);
            key[29] = '_';
            for (size_t i = 30; i < 70; ++i) key[i] = "0123456789aBcDeF"[i % 16];
        }
        break;
    case 829:
        memcpy(key, "ey", 2); key[32] = '.';
        memcpy(key + 33, "ey", 2); key[235] = '.';
        break;
    case 100:
        if (entry->version == 1) { key[10] = '_'; key[22] = '-'; }
        else {
            memcpy(key, "cfut_", 5);
            for (size_t i = 45; i < 53; ++i) key[i] = "0123456789abcdef"[i % 16];
        }
        break;
    case 58:
        if (entry->version == 1) {
            for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        } else {
            memcpy(key, "cfk_", 4);
            for (size_t i = 44; i < 52; ++i) key[i] = "0123456789abcdef"[i % 16];
        }
        secondary = "briar7@fixture.invalid";
        secondary_name = "email";
        break;
    case 226:
        test_secret(secondary_buffer, 50, 7);
        secondary = secondary_buffer;
        secondary_name = "id";
        break;
    case 39:
        test_secret(secondary_buffer, 32, 7);
        secondary = secondary_buffer;
        secondary_name = "api_key";
        break;
    case 211:
        secondary = key; /* Identical source patterns retain the self-pair. */
        secondary_name = "id";
        break;
    case 683:
        secondary = "briar7.as.deputy.com"; /* Required host stays hidden. */
        break;
    case 863:
        secondary = "B7c9D2e5F6g8H3j4K1m0"; /* Required API secret stays hidden. */
        break;
    case 382:
        secondary = "briar7@fixture.invalid"; /* Required bare email is hidden. */
        break;
    case 711:
        for (size_t i = 0; i < 32; ++i) key[i] = "0123456789abcdef"[i % 16];
        secondary = "briar7@fixture.invalid"; /* Required email is hidden from results. */
        break;
    case 5:
        /* Public scalar ONE, short SEC1 scalar and no supplied public point. */
        strcpy(key, "-----BEGIN EC PRIVATE KEY-----\nMBICAQEEAQGgCgYIKoZIzj0DAQc=\n-----END EC PRIVATE KEY-----");
        secondary = "organizations/ORG__123-AB_C-de_F-GHI_-abcdefgh1234/apiKeys/KEY__123-ZZ__-aaaa-bbbb-GHIJklmn5678";
        secondary_name = "key_name";
        break;
    case 62:
        memcpy(key, "dapi", 4);
        for (size_t i = 4; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        secondary = "briar7.cloud.databricks.com";
        secondary_name = "domain";
        break;
    case 749:
        memcpy(key, "live_", 5);
        break;
    case 823:
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[8] = key[13] = key[18] = key[23] = '-'; /* No UUID version/variant validation. */
        break;
    case 960:
        key[0] = 'g'; key[8] = key[13] = key[18] = key[23] = '-';
        break;
    case 805: case 844:
        for (size_t i = 0; i < 40; ++i) key[i] = "0123456789abcdef"[i % 16];
        break;
    case 525:
        key[4] = ':'; key[13] = '_';
        break;
    case 324: case 554:
        for (size_t i = 0; i < entry->key_len; ++i) if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
        if (entry->type == 554) key[0] = 'G'; /* Nonhex, nongrouped source grammar. */
        key[12] = '-';
        break;
    case 59:
        memcpy(key, "v1.0-", 5);
        break;
    case 1048:
        strcpy(key, "001726354809273");
        secondary = "Briar7";
        secondary_name = "cloud_name";
        break;
    case 650:
        test_secret(secondary_buffer, 32, 7);
        secondary = secondary_buffer;
        secondary_name = "organization";
        break;
    case 189:
        strcpy(key, "17263");
        secondary = "b7C9d2E5f6G8h3J4k1M0n2P4";
        secondary_name = "token";
        break;
    case 209:
        strcpy(key, "G7H8IJKL-M9N0-OPQR-STUV-WXYZ1234ABCD");
        secondary = "briar7@fixture.invalid";
        secondary_name = "id";
        break;
    case 215:
        memcpy(key, "api_", 4);
        key[20] = '.';
        break;
    case 307:
        secondary = "briar7";
        secondary_name = "id";
        break;
    case 366:
        memcpy(key, "pk_1726354_", 11);
        for (size_t i = 11; i < 43; ++i) if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
        break;
    case 710:
        strcpy(key, "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3");
        break;
    case 456:
        strcpy(key, "briar7.clickhelp.co"); /* Raw is portal, not the hidden API key. */
        secondary = "briar7@fixture.invalid";
        secondary_name = "email";
        break;
    case 709:
        secondary = "briar7@example.test";
        secondary_name = "email";
        break;
    case 187:
        strcpy(key, "sk_B7c9d2e5-F6a8-b3C4-d1E0-f2A4b6C8d1e3");
        secondary = "cus_Ab3dE6gH9jK2mN5pQ8sT1vW4xY";
        secondary_name = "id";
        break;
    case 739:
        secondary = "ab172635480";
        secondary_name = "user_id";
        break;
    case 643:
        memcpy(key, "pk_", 3);
        break;
    case 648:
        secondary = key; /* Identical occurrence patterns include the self-pair. */
        secondary_name = "id";
        break;
    case 524:
        test_secret(secondary_buffer, 36, 11);
        secondary = secondary_buffer;
        secondary_name = "username";
        break;
    case 708:
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        secondary = "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3";
        secondary_name = "project_id";
        break;
    case 685:
        strcpy(key, "B7C-D9E-F2G-H5J");
        secondary = "briar7";
        secondary_name = "username";
        break;
    case 833:
        secondary = "A7C9D2E5-F6A8-B3C4-D1E0-B2A4C6D8E1F3A";
        secondary_name = "id";
        break;
    case 828:
        snprintf(key, sizeof(key), "f7c9d2e5b6a8f3c4d1e0b2a4c6d8e1f3");
        secondary = "z9y8x7w6v5u4t3s2";
        break;
    case 1003:
        test_secret(secondary_buffer, 32, 11);
        secondary = secondary_buffer;
        secondary_name = "client_secret";
        break;
    case 512:
        test_secret(secondary_buffer, 24, 11);
        secondary = secondary_buffer;
        secondary_name = "key";
        break;
    case 565:
        memcpy(key, "ey", 2);
        memcpy(key + 11, "!ey", 3);
        key[23] = '~';
        break;
    case 302:
        memcpy(key, "AIzaSy", 6);
        break;
    case 908:
        snprintf(key, sizeof(key), "A123a0f9-1a2b-3c4d-5e6f-0123456789ab");
        break;
    case 506:
        memcpy(key, "pri_", 4);
        for (size_t i = 4; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        break;
    case 953:
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[32] = '-';
        break;
    case 150:
    case 254:
    case 317:
    case 598:
    case 602:
    case 707:
    case 867:
    case 585:
    case 457:
    case 458:
    case 511:
    case 1007:
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        break;
    case 212:
        memcpy(key, "sk_live_", 8);
        test_secret(secondary_buffer, 40, 7);
        secondary = secondary_buffer;
        secondary_name = "id";
        break;
    case 733:
        memcpy(key, "0007-", 5);
        for (size_t i = 5; i < 45; ++i) key[i] = "0123456789abcdef"[i % 16];
        break;
    case 910:
        for (size_t i = 0; i < entry->key_len; ++i)
            if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
        break;
    case 522:
        for (size_t i = 0; i < 32; ++i) key[i] = "0123456789ABCDEF"[i % 16];
        break;
    case 933:
        memcpy(key, "sk-ant-api03-", 13);
        key[106] = key[107] = 'A';
        break;
    case 1032:
        for (size_t i = 0; i < 32; ++i) key[i] = "0123456789ABCDEF"[i % 16];
        secondary = "b7c9d2e5f6a8b3c4d1e0f2a4b6c8d0e2";
        secondary_name = "client_id";
        break;
    case 181:
    case 1042:
        secondary = "synthetic-fixture.jfrog.io";
        secondary_name = "domain";
        break;
    case 1046:
        secondary = "https://jira.invalid";
        secondary_name = "url";
        break;
    case 1047:
        secondary = "https://confluence.invalid";
        secondary_name = "url";
        break;
    case 1045:
        secondary = "https://bitbucket.invalid";
        secondary_name = "url";
        break;
    case 1014: strcpy(key, "Native7.v1.Synthetic_-Payload.1a2b3c"); break;
    case 1015:
        memcpy(key, "patN7c4P9d2R5s8T1.", 18);
        for (size_t i = 0; i < 64; ++i) key[18 + i] = "0123456789abcdef"[i % 16];
        key[82] = '\0';
        break;
    }
    if (entry->type == 256)
        snprintf(input, sizeof(input), "%s %s", entry->keyword, key); /* One occurrence, both patterns. */
    else if (entry->type == 456)
        snprintf(input, sizeof(input), "%s\n%s\nsecret AbCd0123EfGh4567IjKl8901", key, secondary);
    else if (entry->type == 1025)
        snprintf(input, sizeof(input), "Endpoint=%s;Id=%s;Secret=AQIDBA==", secondary, key);
    else if (entry->type == 958)
        snprintf(input, sizeof(input), "%s.azurecr.io\n%s", secondary, key);
    else if (entry->type == 3 && entry->version == 1)
        snprintf(input, sizeof(input), "azure\nclient_id a6b39f20-17c4-4d85-9e62-0f3a7b1c5d98\nsecret '%s'\n", key);
    else if (entry->type == 3)
        snprintf(input, sizeof(input), "%s", key);
    else if (session)
        snprintf(input, sizeof(input), "%s\n%s\n%s", key, secondary, session);
    else if (entry->type == 648)
        snprintf(input, sizeof(input), "caspio %s\ncaspio region7q", key);
    else if (entry->type == 756)
        snprintf(input, sizeof(input), "browserstackKey %s\nbrowserstackUser %s", key, secondary);
    else if (entry->type == 1048)
        snprintf(input, sizeof(input), "cloudinary name %s\ncloudinary key %s\ncloudinary secret %s", secondary, key, cloudinary_secret);
    else if (entry->type == 1003)
        snprintf(input, sizeof(input), "box id %s\nsecret %s", key, secondary);
    else if (entry->type == 512)
        snprintf(input, sizeof(input), "bitmex %s\nbitmex %s\n", secondary, key);
    else if (entry->type == 307 || entry->type == 385 || entry->type == 685)
        /* Context-first avoids capturing the repeated provider word as ID/user. */
        snprintf(input, sizeof(input), "%s %s\n%s %s", entry->keyword, secondary, entry->keyword, key);
    else if (entry->type == 322)
        snprintf(input, sizeof(input), "appcues %s\nappcues %s\nappcues 00427", key, secondary);
    else if (entry->type == 197)
        snprintf(input, sizeof(input), "token %s\nsecret %s", key, secondary);
    else if (entry->type == 802)
        snprintf(input, sizeof(input), "aha %s\n%s", key, secondary);
    else if (entry->type == 1007)
        snprintf(input, sizeof(input), "briar.openai.azure.com\napi_key %s", key);
    else if (entry->type == 931)
        snprintf(input, sizeof(input), "DefaultEndpointsProtocol=https;AccountName=%s;AccountKey=%s;EndpointSuffix=core.windows.net", secondary, key);
    else if (entry->type == 179)
        snprintf(input, sizeof(input), "anypoint %s\norg %s", key, secondary);
    else if (entry->type == 55)
        snprintf(input, sizeof(input), "auth0 %s\n%s\nfixture-tenant.us.auth0.com", secondary, key);
    else if (entry->type == 1045)
        snprintf(input, sizeof(input), "%s\nbitbucket %s", key, secondary);
    else if (entry->type == 211)
        snprintf(input, sizeof(input), "customerio %s", key); /* One occurrence, one self-pair. */
    else if (entry->type == 921)
        snprintf(input, sizeof(input), "docker %s\ndocker user=%s", key, secondary);
    else if (entry->type == 325)
        snprintf(input, sizeof(input), "%s\npass %s", key, secondary);
    else if (entry->type == 919)
        snprintf(input, sizeof(input), "docusign\nintegration %s\nsecret %s", key, secondary);
    else if (secondary)
        snprintf(input, sizeof(input), "%s %s\n%s %s", entry->keyword, key, entry->keyword, secondary);
    else if (entry->type == 390) snprintf(input, sizeof(input), "%s", key);
    else snprintf(input, sizeof(input), "%s %s", entry->keyword, key);

    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (entry->type == 42 || entry->type == 56 || entry->type == 386 || entry->type == 180 || entry->type == 282 ? 2u : 1u));
    const br_result *result = &results.items[0];
    CHECK(result->detector_type == entry->type);
    CHECK(result->raw.len == entry->key_len && !memcmp(result->raw.data, key, entry->key_len));
    CHECK(!result->verified && !result->verification_error);
    if (entry->type == 456) {
        CHECK(!result->primary_secret.data && !result->primary_secret.len);
        CHECK(!result->primary_line && !result->chunk_offset_set);
    }
    br_json *part = NULL;
    if (entry->type == 56) {
        for (size_t i = 0; i < 2; ++i) {
            test_key_result(&results.items[i], 56, i ? secondary : key, "key");
            CHECK(!results.items[i].verified && !results.items[i].verification_error);
        }
        br_results_clear(&results);
        return;
    }
    if (entry->type == 828 || entry->type == 711 || entry->type == 382 || entry->type == 863 || entry->type == 683 || entry->type == 821 || entry->type == 639) {
        test_key_result(result, entry->type, key, "key"); /* Required counterpart stays hidden. */
        br_results_clear(&results);
        return;
    }
    if (entry->type == 1029) {
        CHECK(json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "username", &part));
        CHECK(!strcmp(json_object_get_string(part), "briar7"));
        CHECK(json_object_object_get_ex(result->secret_parts, "password", &part));
        CHECK(!strcmp(json_object_get_string(part), key + 7));
        CHECK(!result->raw_v2.data && !result->raw_v2.len);
        CHECK(!result->primary_secret.data && !result->primary_secret.len);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 307 || entry->type == 196) CHECK(result->extra_data && json_object_object_length(result->extra_data) == 0);
    if (entry->type == 58 || entry->type == 65) CHECK(!result->extra_data && result->redacted && !strcmp(result->redacted, secondary));
    if (entry->type == 919) CHECK(!result->extra_data && result->redacted && !strcmp(result->redacted, key));
    if (entry->type == 100) CHECK(!result->extra_data && !result->redacted); /* No invented version metadata. */
    if (entry->type == 142) {
        if (entry->version == 1) CHECK(result->extra_data && json_object_object_length(result->extra_data) == 0);
        else CHECK(!result->extra_data);
    }
    if (entry->type == 4 || entry->type == 430 || entry->type == 333) {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, entry->type == 4 ? "Version" : "version", &part));
        CHECK(!strcmp(json_object_get_string(part), entry->version == 1 ? "1" : "2"));
    }
    if (entry->type == 103) {
        CHECK(result->redacted && strlen(result->redacted) == 7);
        CHECK(!memcmp(result->redacted, "...", 3) && !strcmp(result->redacted + 3, key + 45));
    }
    if (entry->type == 39) {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "Type", &part));
        CHECK(!strcmp(json_object_get_string(part), "Application+APIKey"));
    }
    if (entry->type == 1059) {
        CHECK(result->redacted && strlen(result->redacted) == 18);
        CHECK(!memcmp(result->redacted, key, 15) && !strcmp(result->redacted + 15, "..."));
    }
    if (entry->type == 1053) {
        CHECK(result->redacted && strlen(result->redacted) == 11);
        CHECK(!memcmp(result->redacted, key, 8) && !strcmp(result->redacted + 8, "..."));
    }
    const char *key_name = entry->type == 919 || entry->type == 180 ? "id" : entry->type == 325 ? "email" : entry->type == 921 ? "pat" : entry->type == 39 ? "app_key" : (entry->type == 1048 || entry->type == 1043) ? "api_key" : entry->type == 456 ? "url" : entry->type == 1003 ? "client_id" : entry->type == 512 ? "secret" : entry->type == 1025 ? "id" : (entry->type == 1018 || entry->type == 958) ? "password" : entry->type == 931 ? "account_key" : (entry->type == 957 || entry->type == 1019 || entry->type == 1024 || entry->type == 975) ? "url" : (entry->type == 2 || entry->type == 959) ? "access_key_id" : entry->type == 1045 ? "secret" :
                           entry->type == 1032 || entry->type == 55 ? "client_secret" :
                           entry->type == 375 || entry->type == 1014 || entry->type == 1015 ||
                           entry->type == 181 || entry->type == 1042 || entry->type == 110 ||
                           entry->type == 1047 || entry->type == 1046 || entry->type == 1053 || entry->type == 524 || entry->type == 62 || entry->type == 18 || entry->type == 1059 ? "token" : "key";
    CHECK(json_object_object_get_ex(result->secret_parts, key_name, &part));
    CHECK(!strcmp(json_object_get_string(part), key));
    CHECK(json_object_object_length(result->secret_parts) == (session || entry->type == 1025 || entry->type == 648 || entry->type == 739 || entry->type == 1048 ? 3 : secondary ? 2 : 1));
    if (entry->type == 1048) {
        CHECK(json_object_object_get_ex(result->secret_parts, "api_secret", &part));
        CHECK(!strcmp(json_object_get_string(part), cloudinary_secret));
        CHECK(!result->extra_data && !result->redacted);
    }
    if (entry->type == 1025) {
        CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
        CHECK(!strcmp(json_object_get_string(part), "AQIDBA=="));
    }
    if (entry->type == 739) {
        CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part));
        CHECK(!strcmp(json_object_get_string(part), key)); /* Identical key/secret patterns include self. */
    }
    if (entry->type == 648) {
        CHECK(json_object_object_get_ex(result->secret_parts, "domain", &part));
        CHECK(!strcmp(json_object_get_string(part), "region7q"));
    }
    if (session) {
        CHECK(json_object_object_get_ex(result->secret_parts, "session_token", &part));
        CHECK(!strcmp(json_object_get_string(part), session));
    }
    if (secondary) {
        CHECK(json_object_object_get_ex(result->secret_parts, secondary_name, &part));
        CHECK(!strcmp(json_object_get_string(part), secondary));
        char raw_v2[sizeof(key) + sizeof(secondary_buffer) + sizeof(session_buffer) + 2];
        if (entry->type == 5) snprintf(raw_v2, sizeof(raw_v2), "%s:%s", secondary, key);
        else if (entry->type == 386) snprintf(raw_v2, sizeof(raw_v2), "%s:%s", key, secondary);
        else if (entry->type == 1048) snprintf(raw_v2, sizeof(raw_v2), "%s:%s:%s", secondary, key, cloudinary_secret);
        else if (entry->type == 648) snprintf(raw_v2, sizeof(raw_v2), "%s%sregion7q", key, secondary);
        else if (entry->type == 1025) snprintf(raw_v2, sizeof(raw_v2), "Endpoint=%s;Id=%s;Secret=AQIDBA==", secondary, key);
        else if (entry->type == 958) snprintf(raw_v2, sizeof(raw_v2), "{\"username\":\"%s\",\"password\":\"%s\"}", secondary, key);
        else if (session) snprintf(raw_v2, sizeof(raw_v2), "%s:%s:%s", key, secondary, session);
        else if (entry->type == 931) snprintf(raw_v2, sizeof(raw_v2), "{\"accountName\":\"%s\",\"accountKey\":\"%s\"}", secondary, key);
        else if (entry->type == 971) snprintf(raw_v2, sizeof(raw_v2), "key: %s account_url: %s", key, secondary);
        else if (entry->type == 55 || entry->type == 1018 || entry->type == 512 || entry->type == 708 || entry->type == 739) snprintf(raw_v2, sizeof(raw_v2), "%s%s", secondary, key);
        else if (entry->type == 170 || entry->type == 1032 || entry->type == 1052 || entry->type == 921) snprintf(raw_v2, sizeof(raw_v2), "%s:%s", secondary, key);
        else snprintf(raw_v2, sizeof(raw_v2), entry->type == 1019 || entry->type == 1024 || entry->type == 2 || entry->type == 307 || entry->type == 375 || entry->type == 1045 ||
                      entry->type == 1047 || entry->type == 1046 ? "%s:%s" : "%s%s", key, secondary);
        CHECK(result->raw_v2.len == strlen(raw_v2));
        CHECK(!memcmp(result->raw_v2.data, raw_v2, strlen(raw_v2)));
    } else CHECK(!result->raw_v2.data && !result->raw_v2.len);
    br_results_clear(&results);
}

static void feature_gate_tests(int32_t type, const char *flag)
{
    br_detector gated = {.type = type, .version = 0, .custom_name = ""};
    br_detector disabled = {.type = 384, .version = 0, .custom_name = ""};
    br_detector enabled = {.type = 239, .version = 0, .custom_name = ""};
    br_json *flags = json_object_new_object();
    CHECK(flags && br_detector_is_default(&gated, NULL));
    CHECK(br_detector_is_default(&gated, flags));
    CHECK(!json_object_object_add(flags, "all", json_object_new_boolean(true)));
    CHECK(br_detector_is_default(&gated, flags)); /* Unrelated keys inherit OSS defaults. */
    CHECK(!json_object_object_add(flags, flag, json_object_new_boolean(false)));
    CHECK(!br_detector_is_default(&gated, flags)); /* Explicit package atomic-zero state. */
    CHECK(br_detector_is_default(&enabled, flags) && !br_detector_is_default(&disabled, flags));
    CHECK(!json_object_object_add(flags, flag, json_object_new_string("true")));
    CHECK(!br_detector_is_default(&gated, flags));
    CHECK(!json_object_object_add(flags, flag, json_object_new_int(1)));
    CHECK(!br_detector_is_default(&gated, flags));
    CHECK(!json_object_object_add(flags, flag, NULL));
    CHECK(!br_detector_is_default(&gated, flags));
    CHECK(!json_object_object_add(flags, flag, json_object_new_boolean(true)));
    CHECK(br_detector_is_default(&gated, flags) && !br_detector_is_default(&disabled, flags));
    gated.version = 1;
    CHECK(!br_detector_is_default(&gated, flags));
    gated.version = 0; gated.custom_name = "custom";
    CHECK(!br_detector_is_default(&gated, flags));
    gated.custom_name = "";
    br_json *invalid = json_object_new_boolean(true);
    CHECK(invalid && !br_detector_is_default(&gated, invalid));
    CHECK(br_detector_is_default(&enabled, invalid));
    json_object_put(invalid); json_object_put(flags);
}

static void cloudflare_feature_gate_tests(int32_t type, const char *flag)
{
    br_detector legacy = {.type = type, .version = 1, .custom_name = ""};
    br_detector modern = {.type = type, .version = 2, .custom_name = ""};
    br_detector enabled = {.type = 239, .version = 0, .custom_name = ""};
    br_detector disabled = {.type = 384, .version = 0, .custom_name = ""};
    br_json *flags = json_object_new_object();
    CHECK(flags && br_detector_is_default(&legacy, NULL) && br_detector_is_default(&modern, NULL));
    CHECK(br_detector_is_default(&legacy, flags) && br_detector_is_default(&modern, flags));
    CHECK(!json_object_object_add(flags, "all", json_object_new_boolean(true)));
    CHECK(br_detector_is_default(&modern, flags));
    CHECK(!json_object_object_add(flags, flag, json_object_new_boolean(false)));
    CHECK(br_detector_is_default(&legacy, flags) && !br_detector_is_default(&modern, flags));
    CHECK(br_detector_is_default(&enabled, flags) && !br_detector_is_default(&disabled, flags));
    CHECK(!json_object_object_add(flags, flag, json_object_new_string("true")));
    CHECK(!br_detector_is_default(&modern, flags));
    CHECK(!json_object_object_add(flags, flag, json_object_new_int(1)));
    CHECK(!br_detector_is_default(&modern, flags));
    CHECK(!json_object_object_add(flags, flag, NULL));
    CHECK(!br_detector_is_default(&modern, flags));
    CHECK(!json_object_object_add(flags, flag, json_object_new_boolean(true)));
    CHECK(br_detector_is_default(&legacy, flags) && br_detector_is_default(&modern, flags));
    modern.version = 0; CHECK(!br_detector_is_default(&modern, flags));
    modern.version = 3; CHECK(!br_detector_is_default(&modern, flags));
    modern.version = 2; modern.custom_name = "custom"; CHECK(!br_detector_is_default(&modern, flags));
    modern.custom_name = "";
    br_json *invalid = json_object_new_boolean(true);
    CHECK(invalid && br_detector_is_default(&legacy, invalid) && !br_detector_is_default(&modern, invalid));
    CHECK(br_detector_is_default(&enabled, invalid));
    json_object_put(invalid); json_object_put(flags);
}

int main(void)
{
    const br_detector *const *detectors = NULL;
    size_t count = 0;
    char *error = NULL;
    CHECK(BR_ABI_REVISION == 1);
    feature_gate_tests(1053, "BraintrustDetectorEnabled");
    feature_gate_tests(1059, "DuffelTokenDetectorEnabled");
    feature_gate_tests(1063, "DuoDetectorEnabled");
    feature_gate_tests(1048, "CloudinaryDetectorEnabled");
    feature_gate_tests(1043, "DatadogApiKeyDetectorEnabled");
    cloudflare_feature_gate_tests(100, "CloudflareApiTokenV2DetectorEnabled");
    cloudflare_feature_gate_tests(58, "CloudflareGlobalApiKeyV2DetectorEnabled");
    CHECK(br_registry(&detectors, &count, &error) == 0 && error == NULL);
    CHECK(count == sizeof(expected) / sizeof(expected[0]));
    CHECK(!br_detector_type_name(-1));
    CHECK(!br_detector_type_name(1)); /* AMQP has no implementation yet. */
    CHECK(!br_detector_is_default(NULL, NULL));
    br_detector missing = {.type = 1};
    CHECK(!br_detector_is_default(&missing, NULL));
    br_json *flags = json_object_new_object();
    CHECK(flags && json_object_object_add(flags, "all", json_object_new_boolean(true)) == 0);
    for (size_t i = 0; i < count; ++i) {
        const br_detector *detector = detectors[i];
        const registration *entry = &expected[i];
        CHECK(detector->type == entry->type && detector->version == entry->version);
        CHECK(!strcmp(detector->name, entry->name));
        CHECK(!strcmp(br_detector_type_name(detector->type), entry->name));
        CHECK(detector->description && detector->description[0]);
        CHECK(detector->custom_name && !detector->custom_name[0]);
        CHECK(detector->nkeywords == (entry->type == 931 ? 15u : entry->type == 196 || (entry->type == 3 && entry->version == 1) ? 6u :
              entry->type == 2 || entry->type == 181 || entry->type == 1047 || entry->type == 897 || (entry->type == 921 && entry->version == 2) ? 3u :
              entry->type == 282 || entry->type == 1059 || entry->type == 18 || entry->type == 39 || entry->type == 1043 || entry->type == 62 || entry->type == 343 || entry->type == 954 || entry->type == 189 || entry->type == 307 || entry->type == 907 || entry->type == 920 || entry->type == 170 || entry->type == 933 || entry->type == 1046 || entry->type == 971 || entry->type == 1013 || entry->type == 1018 || entry->type == 1029 || entry->type == 603 || entry->type == 975 || entry->type == 739 || (entry->type == 100 && entry->version == 2) || (entry->type == 430 && entry->version == 2) ? 2u : 1u));
        CHECK(!strcmp(detector->keywords[0], entry->keyword));
        if (entry->type == 3 && entry->version == 1) {
            const char *aliases[] = {"az", "entra", "msal", "login.microsoftonline.com", ".onmicrosoft.com"};
            for (size_t j = 0; j < 5; ++j) CHECK(!strcmp(detector->keywords[j + 1], aliases[j]));
        }
        if (entry->type == 196) {
            const char *aliases[] = {"dp.pt.", "dp.st", "dp.sa.", "dp.scim.", "dp.audit."};
            for (size_t j = 0; j < 5; ++j) CHECK(!strcmp(detector->keywords[j + 1], aliases[j]));
        }
        if (entry->type == 430 && entry->version == 2) CHECK(!strcmp(detector->keywords[1], "bb_ma_"));
        if (entry->type == 39 || entry->type == 1043) CHECK(!strcmp(detector->keywords[1], "ddog-gov"));
        if (entry->type == 920) CHECK(!strcmp(detector->keywords[1], "couchbases://"));
        if (entry->type == 954) CHECK(!strcmp(detector->keywords[1], "ddw_"));
        if (entry->type == 343) CHECK(!strcmp(detector->keywords[1], "\\\"auths\\"));
        if (entry->type == 18) CHECK(!strcmp(detector->keywords[1], "sl."));
        if (entry->type == 1059) CHECK(!strcmp(detector->keywords[1], "duffel_live_"));
        if (entry->type == 282) CHECK(!strcmp(detector->keywords[1], "easy-insight"));
        if (entry->type == 603) CHECK(!strcmp(detector->keywords[1], "runscope"));
        if (entry->type == 307) CHECK(!strcmp(detector->keywords[1], "clientary"));
        if (entry->type == 189) CHECK(!strcmp(detector->keywords[1], "textanywhere"));
        if (entry->type == 100 && entry->version == 2) CHECK(!strcmp(detector->keywords[1], "cfat_"));
        if (entry->type == 1029) CHECK(!strcmp(detector->keywords[1], "ATBB"));
        if (entry->type == 1018) CHECK(!strcmp(detector->keywords[1], ".scm.azure-api.net"));
        if (entry->type == 975) CHECK(!strcmp(detector->keywords[1], ".blob.core.windows.net"));
        if (entry->type == 1013) CHECK(!strcmp(detector->keywords[1], "1.A"));
        if (entry->type == 971) CHECK(!strcmp(detector->keywords[1], ".table.cosmos.azure.com"));
        if (entry->type == 907) CHECK(!strcmp(detector->keywords[1], "alcht_"));
        if (entry->type == 170) CHECK(!strcmp(detector->keywords[1], "docsearch"));
        if (entry->type == 933) CHECK(!strcmp(detector->keywords[1], "sk-ant-admin01"));
        if (entry->type == 2) {
            CHECK(!strcmp(detector->keywords[1], "ABIA"));
            CHECK(!strcmp(detector->keywords[2], "ACCA"));
        }
        if (entry->type == 921 && entry->version == 2) {
            CHECK(!strcmp(detector->keywords[1], "dckr_pat_"));
            CHECK(!strcmp(detector->keywords[2], "dckr_oat_"));
        }
        if (entry->type == 897) {
            CHECK(!strcmp(detector->keywords[1], "doo_v1_"));
            CHECK(!strcmp(detector->keywords[2], "dor_v1_"));
        }
        if (entry->type == 1046) CHECK(!strcmp(detector->keywords[1], "atlassian"));
        if (entry->type == 1047) {
            CHECK(!strcmp(detector->keywords[1], "atlassian"));
            CHECK(!strcmp(detector->keywords[2], "wiki"));
        }
        if (entry->type == 181) {
            CHECK(!strcmp(detector->keywords[1], "jfrog.io"));
            CHECK(!strcmp(detector->keywords[2], "AKCp"));
        }
        CHECK(detector->max_secret_size == (entry->type == 110 ? 5000 : entry->type == 343 || entry->type == 18 ? 4096 : entry->type == 1013 ? 2048 : entry->type == 829 ? 1300 : -1) &&
              detector->start_offset == (entry->type == 1013 ? 4096 : -1) &&
              detector->max_credential_span == entry->span);
        CHECK(detector->state && detector->scan);
        if (entry->type == 957 || entry->type == 1019 || entry->type == 958 || entry->type == 1024 || entry->type == 975) {
            char *reason = NULL;
            CHECK(detector->false_positive && !detector->false_positive(detector, NULL, &reason));
            CHECK(reason && !strcmp(reason, ""));
            free(reason);
        } else CHECK(!detector->false_positive);
        if (entry->type == 2 || entry->type == 959) CHECK(detector->clean && detector->clean_always);
        else CHECK(!detector->clean && !detector->clean_always);
        if (entry->type == 181 || entry->type == 1042 || entry->type == 1047) {
            CHECK(detector->validate_endpoints && detector->cloud_endpoint);
            CHECK(!detector->cloud_endpoint[0]);
        } else if (entry->type == 39 || entry->type == 1043) {
            CHECK(detector->validate_endpoints && detector->cloud_endpoint);
            CHECK(!strcmp(detector->cloud_endpoint, "https://api.datadoghq.com"));
        } else if (entry->type == 1045 || entry->type == 1046) {
            CHECK(detector->validate_endpoints && !detector->cloud_endpoint);
        } else CHECK(!detector->validate_endpoints && !detector->cloud_endpoint);
        CHECK(br_detector_is_default(detector, NULL) == entry->enabled);
        CHECK(br_detector_is_default(detector, flags) == entry->enabled);
        br_detector copied = *detector;
        CHECK(br_detector_is_default(&copied, NULL) == entry->enabled);
        copied.version = 77;
        CHECK(!br_detector_is_default(&copied, NULL));
        copied.version = detector->version;
        copied.custom_name = "custom";
        CHECK(!br_detector_is_default(&copied, NULL));
        for (size_t j = 0; j < i; ++j) {
            CHECK(detector != detectors[j]);
            CHECK(detector->type != detectors[j]->type || detector->version != detectors[j]->version);
        }
        check_dispatch(detector, entry);
    }
    json_object_put(flags);
    const br_detector *const *again = NULL;
    size_t nagain = 0;
    CHECK(br_registry(&again, &nagain, &error) == 0 && !error && again == detectors && nagain == count);
    CHECK(br_registry(NULL, &nagain, &error) != 0 && error && nagain == 0);
    free(error); error = NULL;
    CHECK(br_registry(&again, NULL, &error) != 0 && error && !again);
    free(error);
    return test_finish("Registry identities, defaults and dispatch");
}
