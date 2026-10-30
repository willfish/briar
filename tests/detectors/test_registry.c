/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../support/detector_test.h"
#include "../../src/detectors/detectors.h"

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
    {727, 0, "EightxEight", "8x8", 43, true, 1024},
    {112, 0, "ElasticEmail", "elasticemail", 96, true, -1},
    {994, 1, "ElevenLabs", "elevenlabs", 32, true, -1},
    {994, 2, "ElevenLabs", "elevenlabs", 51, true, -1},
    {652, 0, "Enablex", "enablex", 36, true, 1024},
    {993, 0, "EndorLabs", "endr+", 21, true, -1},
    {405, 0, "Enigma", "enigma", 40, true, -1},
    {923, 0, "EnvoyApiKey", "envoy", 220, true, -1},
    {990, 0, "Eraser", "eraser", 20, true, -1},
    {905, 0, "Etherscan", "etherscan", 34, true, -1},
    {283, 0, "Ethplorer", "ethplorer", 22, true, -1},
    {962, 0, "Eventbrite", "eventbrite", 20, true, -1},
    {284, 0, "Everhour", "everhour", 32, true, -1},
    {360, 0, "ExchangeRateAPI", "exchangerate", 24, true, -1},
    {379, 0, "ExchangeRatesAPI", "exchangerates", 32, true, -1},
    {771, 0, "ExportSDK", "exportsdk", 46, true, 1024},
    {784, 0, "ExtractorAPI", "extractorapi", 40, true, -1},
    {40, 0, "FacebookOAuth", "facebook", 32, true, 1024},
    {416, 0, "FacePlusPlus", "faceplusplus", 32, true, 1024},
    {636, 0, "FastForex", "fastforex", 28, true, -1},
    {68, 0, "FastlyPersonalToken", "fastly", 32, true, -1},
    {238, 0, "Feedier", "feedier", 32, true, -1},
    {592, 0, "Fetchrss", "fetchrss", 40, true, -1},
    {808, 0, "Fibery", ".fibery.io", 44, true, 1024},
    {113, 1, "FigmaPersonalAccessToken", "figma", 43, true, -1},
    {113, 2, "FigmaPersonalAccessToken", "figma", 45, true, -1},
    {113, 3, "FigmaPersonalAccessToken", "figp_", 59, true, -1},
    {527, 0, "FileIO", "fileio", 39, true, -1},
    {423, 0, "Finage", "finage", 39, true, -1},
    {406, 0, "FinancialModelingPrep", "financialmodelingprep", 32, true, -1},
    {667, 0, "Findl", "findl", 36, true, -1},
    {420, 0, "Finnhub", "finnhub", 20, true, -1},
    {149, 0, "FixerIO", "fixer", 32, true, -1},
    {501, 0, "FlatIO", "flat", 128, true, -1},
    {428, 0, "Fleetbase", "fleetbase", 29, true, -1},
    {1009, 0, "Flexport", "shltm_", 46, true, -1},
    {455, 0, "Flickr", "flickr", 32, true, -1},
    {528, 0, "FlightApi", "flightapi", 24, true, -1},
    {848, 0, "FlightLabs", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9", 127, true, -1},
    {642, 0, "Flightstats", "flightstats", 32, true, 1024},
    {249, 0, "Float", "float", 60, true, -1},
    {265, 0, "FlowFlu", "flowflu", 51, true, 1024},
    {173, 0, "Flutterwave", "FLWSECK-", 42, true, -1},
    {980, 0, "FlyIO", "FlyV1", 510, true, -1},
    {653, 0, "Fmfw", "fmfw", 32, true, 1024},
    {713, 0, "FormBucket", "formbucket", 77, true, -1},
    {812, 0, "Formcraft", "formcraft", 16, true, -1},
    {712, 0, "FormIO", "formio", 331, true, -1},
    {839, 0, "Formsite", "formsite", 32, true, 1024},
    {454, 0, "FourSquare", "foursquare", 48, true, 1024},
    {199, 0, "FrameIO", "fio-u-", 70, true, -1},
    {681, 0, "Freshbooks", "freshbooks", 64, true, 1024},
    {678, 0, "Freshdesk", "freshdesk", 20, true, 1024},
    {427, 0, "Front", "front", 281, true, -1},
    {899, 0, "FTP", "ftp://", 38, true, -1},
    {285, 0, "Fulcrum", "fulcrum", 80, true, -1},
    {394, 1, "Fullstory", "fullstory", 88, true, -1},
    {394, 2, "Fullstory", "fullstory", 104, true, -1},
    {381, 0, "FXMarket", "fxmarket", 20, true, -1},
    {6, 0, "GCP", "provider_x509", sizeof("briar87@offline.invalid") - 1, true, -1},
    {983, 0, "GCPApplicationDefaultCredentials", ".apps.googleusercontent.com", 2, true, -1},
    {696, 0, "Geckoboard", "geckoboard", 44, true, -1},
    {876, 0, "Gemini", "master-", 27, true, 1024},
    {7, 0, "Generic", "pass", 17, false, -1},
    {426, 0, "Gengo", "gengo", 64, true, 1024},
    {529, 0, "Geoapify", "geoapify", 32, true, -1},
    {486, 0, "Geocode", "geocode", 28, true, -1},
    {542, 0, "Geocodify", "geocodify", 40, true, -1},
    {407, 0, "Geocodio", "geocod", 39, true, 1024},
    {286, 0, "GeoIpifi", "ipifi", 32, true, -1},
    {326, 0, "GetEmail", "getemail", 20, false, -1},
    {327, 0, "GetEmails", "getemails", 26, false, 1024},
    {383, 0, "GetGeoAPI", "getgeoapi", 40, true, -1},
    {210, 0, "Getgist", "getgist", 68, true, -1},
    {861, 0, "Getresponse", "getresponse", 32, true, -1},
    {633, 0, "GetSandbox", "getsandbox", 40, true, 1024},
    {8, 1, "Github", "github", 40, true, -1},
    {8, 2, "Github", "ghp_", 40, true, -1},
    {924, 0, "GitHubOauth2", "github", 20, true, 1024},
    {36, 0, "GitHubApp", "github", sizeof("-----BEGIN RSA PRIVATE KEY-----\nQ7r2T9\n-----END RSA PRIVATE KEY-----") - 1, true, 1024},
    {9, 1, "Gitlab", "gitlab", 20, true, -1},
    {9, 2, "Gitlab", "glpat-", 26, true, -1},
    {9, 3, "Gitlab", "glpat-", 46, true, -1},
    {1050, 0, "GitLabOauth2", "gloas-", 70, true, 1024},
    {555, 0, "Gitter", "gitter", 40, true, -1},
    {569, 0, "Glassnode", "glassnode", 27, true, -1},
    {714, 0, "GoCanvas", "gocanvas", 44, true, 1024},
    {184, 0, "GoCardless", "gocardless", 45, true, -1},
    {1008, 1, "GoDaddy", "godaddy", 37, true, -1},
    {1008, 2, "GoDaddy", "godaddy", 35, true, -1},
    {654, 0, "GoodDay", "goodday", 32, true, -1},
    {1041, 0, "GoogleGeminiAPIKey", "aizasy", 39, true, -1},
    {69, 0, "GoogleOauth2", "ya29.", 15, true, -1},
    {830, 0, "Grafana", "glc_eyJ", 67, true, -1},
    {963, 0, "GrafanaServiceAccount", "glsa_", 46, true, 1024},
    {223, 0, "GraphCMS", "graphcms", 1127, true, 1024},
    {436, 0, "Graphhopper", "graphhopper", 36, true, -1},
    {206, 0, "Groovehq", "groovehq", 64, true, -1},
    {988, 0, "Groq", "gsk_", 56, true, -1},
    {763, 0, "GTMetrix", "gtmetrix", 32, true, -1},
    {259, 0, "Guardianapi", "guardianapi", 36, true, -1},
    {792, 0, "Gumroad", "gumroad", 43, true, -1},
    {570, 0, "Guru", "guru", 9, false, 1024},
    {467, 0, "Gyazo", "gyazo", 43, true, -1},
    {507, 0, "Happyscribe", "happyscribe", 24, true, -1},
    {1020, 0, "Harness", "harness", 72, true, -1},
    {260, 0, "Harvest", "harvest", 97, true, 1024},
    {1061, 0, "HashiCorpVaultBatchToken", "hvb.", 54, true, 1024},
    {1036, 0, "HashiCorpVaultAuth", "hashicorp", 36, true, 1024},
    {1062, 0, "HashiCorpVaultToken", "hvs.", 94, true, 1024},
    {1030, 0, "Hasura", "hasura", 64, true, -1},
    {395, 0, "HelloSign", "hellosign", 64, true, -1},
    {164, 0, "HelpCrunch", "helpcrunch", 328, true, -1},
    {153, 0, "Helpscout", "helpscout", 40, true, -1},
    {408, 0, "HereAPI", "hereapi", 43, true, -1},
    {19, 1, "Heroku", "heroku", 36, true, -1},
    {19, 2, "Heroku", "HRKU-AA", 65, true, -1},
    {571, 0, "Hive", "hive", 17, false, 1024},
    {572, 0, "Hiveage", "hiveage", 20, true, -1},
    {361, 0, "HolidayAPI", "holidayapi", 36, true, -1},
    {764, 0, "Holistic", "holistic", 64, true, -1},
    {877, 0, "Honeycomb", "Honeycomb", 22, true, -1},
    {556, 0, "Host", "host.io", 14, true, -1},
    {355, 0, "Html2Pdf", "html2pdf", 64, true, -1},
    {107, 1, "HubSpotApiKey", "hubapi", 36, true, -1},
    {107, 2, "HubSpotApiKey", "pat-na1-", 44, true, -1},
    {926, 0, "HuggingFace", "hf_", 37, true, -1},
    {508, 0, "Humanity", "humanity", 40, true, -1},
    {72, 0, "Hunter", "hunter", 40, true, -1},
    {773, 0, "Hybiscus", "hybiscus", 43, true, -1},
    {459, 0, "Hypertrack", "hypertrack", 54, true, 1024},
    {73, 0, "IbmCloudUserKey", "ibm", 44, false, -1},
    {487, 0, "IconFinder", "iconfinder", 64, true, -1},
    {813, 0, "Iexapis", "iexapis", 35, true, -1},
    {557, 0, "Iexcloud", "iexcloud", 35, true, -1},
    {250, 0, "Imagekit", "imagekit", 36, true, -1},
    {349, 0, "Imagga", "imagga", 72, true, -1},
    {509, 0, "Impala", "impala", 46, true, -1},
    {906, 0, "Infura", "infura", 32, true, -1},
    {271, 0, "Insightly", "insightly", 36, true, -1},
    {856, 0, "Instabot", "instabot", 44, true, -1},
    {941, 0, "Instamojo", "instamojo", 40, true, 1024},
    {156, 0, "Intercom", "intercom", 60, true, -1},
    {858, 0, "Interseller", "interseller", 36, true, -1},
    {987, 0, "Intra42", "s-s4t2ud-", 73, true, 1024},
    {579, 0, "Intrinio", "intrinio", 44, true, -1},
    {689, 0, "InvoiceOcean", "invoiceocean", 20, true, 1024},
    {940, 0, "Ip2location", "ip2location", 32, true, -1},
    {362, 0, "Ipapi", "ipapi", 32, true, -1},
    {356, 0, "IPGeolocation", "ipgeolocation", 32, true, -1},
    {939, 0, "IPInfo", "ipinfo", 14, true, -1},
    {530, 0, "IPinfoDB", "ipinfodb", 64, true, -1},
    {478, 0, "IPQuality", "ipquality", 32, true, -1},
    {133, 0, "IpStack", "ipstack", 32, true, -1},
    {1046, 0, "JiraDataCenterPAT", "jira", 44, true, 1024},
    {287, 0, "Jotform", "jotform", 32, true, -1},
    {131, 0, "Jumpcloud", "jumpcloud", 40, true, -1},
    {295, 0, "Juro", "juro", 40, true, -1},
    {686, 0, "Kanban", "kanban", 12, true, 1024},
    {329, 0, "Leadfeeder", "leadfeeder", 43, true, -1},
    {450, 0, "LocationIQ", "locationiq", 35, true, -1},
    {510, 0, "Loginradius", "loginradius", 36, true, -1},
    {715, 0, "MadKudu", "madkudu", 32, true, -1},
    {228, 0, "Mailerlite", "mailerlite", 32, true, -1},
    {982, 0, "JupiterOne", "jupiterone", 76, true, -1},
    {786, 0, "MagicBell", "magicbell", 40, true, 1024},
    {145, 0, "Mailboxlayer", "mailboxlayer", 32, true, -1},
    {105, 0, "MailJetBasicAuth", "mailjet", 88, true, -1},
    {106, 0, "MailJetSMS", "mailjet", 32, true, -1},
    {853, 0, "Kanbantool", "kanbantool", 12, true, 1024},
    {296, 0, "KarmaCRM", "karmacrm", 20, true, -1},
    {140, 0, "KeenIO", "keen", 64, true, 1024},
    {573, 0, "Kickbox", "kickbox", 65, true, -1},
    {740, 0, "Klipfolio", "klipfolio", 40, true, -1},
    {760, 0, "KnapsackPro", "knapsackpro", 32, true, -1},
    {935, 0, "Klaviyo", "pk_", 37, true, -1},
    {328, 0, "Kontent", "kontent", 36, true, -1},
    {656, 0, "Meistertask", "meistertask", 43, true, -1},
    {111, 0, "MessageBird", "messagebird", 25, true, -1},
    {186, 0, "Kraken", "kraken", 56, true, 1024},
    {736, 0, "KuCoin", "kucoin", 24, true, 1024},
    {272, 0, "Kylas", "kylas", 36, true, -1},
    {1021, 0, "Langfuse", "pk-lf-", 42, true, -1},
    {1028, 0, "LangSmith", "lsv2_pt_", 51, true, -1},
    {489, 0, "LanguageLayer", "languagelayer", 32, true, -1},
    {991, 0, "LarkSuite", "lark", 16, true, 1024},
    {992, 0, "LarkSuiteApiKey", "lark", 20, true, 1024},
    {191, 0, "LaunchDarkly", "api-", 40, true, -1},
    {841, 0, "Lemlist", "lemlist", 32, true, -1},
    {952, 0, "LemonSqueezy", "lemonsqueezy", 864, true, -1},
    {901, 0, "LDAP", "ldaps://", 0, true, 1024},
    {668, 0, "Lendflow", "lendflow", 956, true, 1024},
    {267, 0, "LessAnnoyingCRM", "lessannoyingcrm", 57, true, -1},
    {437, 0, "Lexigram", "lexigram", 301, true, -1},
    {177, 0, "LinearAPI", "lin_api_", 48, true, -1},
    {120, 1, "JiraToken", "atlassian", 24, true, 1024},
    {120, 2, "JiraToken", "atlassian", 54, true, 1024},
    {758, 0, "Loadmill", "loadmill", 40, true, -1},
    {1000, 0, "Meraki", "meraki", 40, true, -1},
    {168, 0, "LineMessaging", "line", 171, false, -1},
    {176, 0, "LineNotify", "linenotify", 43, true, -1},
    {438, 0, "LinkPreview", "linkpreview", 32, true, -1},
    {735, 0, "Livestorm", "livestorm", 243, true, -1},
    {165, 0, "LiveAgent", "liveagent", 32, true, 1024},
    {10, 0, "JDBC", "jdbc", 28, true, 1024},
    {774, 0, "Miro", "miro", 27, true, -1},
    {700, 0, "Mixmax", "mixmax", 36, true, -1},
    {371, 0, "Mixpanel", "mixpanel", 32, false, 1024},
    {682, 0, "Mite", "mite", 16, true, 1024},
    {669, 0, "Moderation", "moderation", 196, true, -1},
    {657, 0, "Mindmeister", "mindmeister", 43, true, -1},
    {820, 0, "MonkeyLearn", "monkeylearn", 40, true, -1},
    {753, 0, "Mockaroo", "mockaroo", 8, true, -1},
    {246, 0, "Monday", "monday", 178, true, -1},
    {157, 0, "Mailmodo", "mailmodo", 31, true, -1},
    {995, 0, "Netsuite", "netsuite", 64, true, 1024},
    {623, 0, "NeutrinoApi", "neutrinoapi", 48, true, 1024},
    {207, 0, "Newsapi", "newsapi", 32, true, -1},
    {896, 0, "NGC", "ngc", 84, true, 1024},
    {543, 0, "Newscatcher", "newscatcher", 43, true, -1},
    {966, 0, "Ngrok", "ngrok", 49, true, -1},
    {121, 0, "NexmoApiKey", "nexmo", 8, true, 1024},
    {698, 0, "Moonclerk", "moonclerk", 32, true, -1},
    {909, 0, "Moralis", "moralis", 64, true, -1},
    {261, 0, "Moosend", "moosend", 36, true, -1},
    {688, 0, "MyIntervals", "myintervals", 11, true, -1},
    {532, 0, "NasdaqDataLink", "nasdaq", 20, false, -1},
    {748, 0, "Mux", "mux", 36, true, 1024},
    {216, 0, "Myfreshworks", "freshworks", 22, true, 1024},
    {268, 0, "Nethunt", "nethunt", 36, true, 1024},
    {691, 0, "Mrticktock", "mrticktock", 20, true, 1024},
    {74, 1, "Netlify", "netlify", 44, true, -1},
    {74, 2, "Netlify", "netlify", 40, true, -1},
    {531, 0, "MediaStack", "mediastack", 32, true, -1},
    {950, 0, "Metabase", "metabase", 36, true, 1024},
    {297, 0, "Metrilo", "metrilo", 16, true, -1},
    {737, 0, "MetaAPI", "metaapi", 64, true, 1024},
    {503, 0, "Mesibo", "mesibo", 64, true, -1},
    {114, 1, "MicrosoftTeamsWebhook", "webhook.office.com", 384, true, 1024},
    {114, 2, "MicrosoftTeamsWebhook", "environment.api.powerplatform.com", 270, true, -1},
};

/* Registration must dispatch real initialized scanners, not metadata stubs. */
static void check_dispatch(const br_detector *detector, const registration *entry)
{
    if (entry->type == 995) {
        char ck[65], cs[65], tk[65], ts[65], account[16], input[420];
        test_secret(ck, 64, 0); test_secret(cs, 64, 7); test_secret(tk, 64, 13); test_secret(ts, 64, 19);
        test_secret(account, 10, 3);
        snprintf(input, sizeof(input),
                 "netsuite consumer key %s\nnetsuite consumer secret %s\nnetsuite token key %s\nnetsuite token secret %s\nnetsuite account id %s",
                 ck, cs, tk, ts, account);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        /* PrefixRegex alternates the three keywords, so each grammar can match
         * more than one candidate in a realistic multi-line credential blob. */
        CHECK(results.len >= 1 && results.items[0].detector_type == 995);
        const br_result *r = &results.items[0];
        CHECK(r->raw.len == 64);
        CHECK(r->raw_v2.len == 128 && !memcmp(r->raw_v2.data, r->raw.data, 64));
        CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
        CHECK(!r->verified && !r->verification_error && !r->extra_data);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 623) {
        char key[49], id[13], input[128]; test_secret(key, 48, 0); test_secret(id, 12, 5);
        snprintf(input, sizeof(input), "neutrinoapi %s\nneutrinoapi %s", key, id);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len >= 1 && results.items[0].detector_type == 623);
        test_key_result(&results.items[0], 623, key, "key");
        br_results_clear(&results);
        return;
    }
    if (entry->type == 896) {
        const char *encoded = "WGtMOGtDWWFaZEpSbWpKTktWQTQ2VWNKYk06VWxhRjFvMEotS2FEUS0za1hkLVBtekktblJLM0VoZEJPMXAw";
        char input[160];
        snprintf(input, sizeof(input), "ngc %s", encoded);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1);
        test_key_result(&results.items[0], 896, encoded, "key");
        br_results_clear(&results);
        return;
    }
    if (entry->type == 966) {
        char key[50], input[80];
        key[0] = '2'; test_secret(key + 1, 26, 0); key[27] = '_'; key[28] = '7'; test_secret(key + 29, 20, 3);
        snprintf(input, sizeof(input), "ngrok %s", key);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1);
        test_key_result(&results.items[0], 966, key, "key");
        br_results_clear(&results);
        return;
    }
    if (entry->type == 121) {
        char key[9], secret[17], input[80];
        test_secret(key, 8, 0); test_secret(secret, 16, 5);
        snprintf(input, sizeof(input), "nexmo %s\nnexmo %s", key, secret);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw.len == 8 && !memcmp(results.items[0].raw.data, key, 8));
        CHECK(results.items[0].raw_v2.len == 24 && !memcmp(results.items[0].raw_v2.data, key, 8) && !memcmp(results.items[0].raw_v2.data + 8, secret, 16));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 748) {
        char key[37], secret[76], input[140];
        test_secret(key, 36, 0);
        for (size_t i = 0; i < 36; ++i) if (key[i] > 'f') key[i] = 'a';
        key[8] = key[13] = key[18] = key[23] = '-';
        test_secret(secret, 75, 0);
        snprintf(input, sizeof(input), "mux %s\nmux %s ", key, secret);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw_v2.len == 111);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 216) {
        char key[23], id[13], input[80];
        test_secret(key, 22, 0); test_secret(id, 12, 5);
        snprintf(input, sizeof(input), "freshworks %s\nfreshworks %s", key, id);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw.len == 22 && !memcmp(results.items[0].raw.data, key, 22));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 268) {
        char key[37], id[27], input[90];
        test_secret(key, 36, 0); test_secret(id, 26, 5);
        snprintf(input, sizeof(input), "nethunt %s\nnethunt %s", key, id);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw.len == 36 && !memcmp(results.items[0].raw.data, key, 36));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 691) {
        /* The keyword must not also appear inside the address, or its own
         * prefixed password grammar yields a second, still source-valid pair. */
        const char *email = "briar7@fixture.invalid";
        char input[110];
        snprintf(input, sizeof(input), "%s\nmrticktock Hunter2Pass", email);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw.len == strlen(email) && !memcmp(results.items[0].raw.data, email, strlen(email)));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 74 && entry->version == 2) {
        char key[41], input[80];
        memcpy(key, "nfp_", 4);
        for (size_t i = 4; i < 40; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[40] = '\0';
        snprintf(input, sizeof(input), "netlify %s", key);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw.len == 40 && results.items[0].extra_data);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 737) {
        char key[65], spell[25], input[120];
        for (size_t i = 0; i < 64; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[64] = '\0';
        for (size_t i = 0; i < 24; ++i) spell[i] = "0123456789abcdef"[(i + 5) % 16];
        spell[24] = '\0';
        snprintf(input, sizeof(input), "metaapi %s\nmetaapi %s", spell, key);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw.len == 64 && !memcmp(results.items[0].raw.data, key, 64));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 503) {
        char key[65], input[90];
        for (size_t i = 0; i < 64; ++i) key[i] = "0123456789ABCDEFabcdef"[i % 22];
        key[64] = '\0';
        snprintf(input, sizeof(input), "mesibo %s", key);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw.len == 64);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 950) {
        char key[37], input[140];
        test_secret(key, 36, 0);
        snprintf(input, sizeof(input), "metabase %s\nmetabase https://briar7.example.com", key);
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].raw_v2.len == 62);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 114 && entry->version == 1) {
        const char *url = "https://briar7.webhook.office.com/webhookb2/b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3@b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3/IncomingWebhook/0123456789abcdef0123456789abcdef/b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3";
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, url, strlen(url));
        CHECK(results.len == 1 && results.items[0].raw.len == strlen(url));
        CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 2);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 114 && entry->version == 2) {
        const char *url = "https://default1234.5.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/0123456789abcdef0123456789abcdef/triggers/manual/paths/invoke?api-version=1&sig=k7m2q9x4z1";
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, url, strlen(url));
        CHECK(results.len == 1 && results.items[0].raw.len == strlen(url));
        CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 1);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 10) {
        const char *connection = "jdbc:sqlite:/data/example.db";
        br_scan_ctx ctx = {0};
        br_results results = test_scan(detector, &ctx, false, connection, strlen(connection));
        CHECK(results.len == 1 && results.items[0].detector_type == 10);
        CHECK(results.items[0].raw.len == strlen(connection) && !memcmp(results.items[0].raw.data, connection, strlen(connection)));
        CHECK(results.items[0].redacted && !strcmp(results.items[0].redacted, connection));
        br_json *value = NULL;
        CHECK(results.items[0].secret_parts && json_object_object_get_ex(results.items[0].secret_parts, "connection_string", &value));
        CHECK(!strcmp(json_object_get_string(value), connection));
        CHECK(!results.items[0].extra_data && !results.items[0].raw_v2.data && !results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 165) {
        const char *domain = "https://briar.ladesk.com";
        char key[33], input[120]; test_secret(key, 32, 7);
        snprintf(input, sizeof(input), "liveagent %s\n%s", key, domain);
        br_results results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 1);
        br_json *value = NULL;
        CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 1);
        CHECK(json_object_object_get_ex(results.items[0].extra_data, "domain", &value) && !strcmp(json_object_get_string(value), domain));
        br_result plain = results.items[0]; plain.extra_data = NULL;
        test_key_result(&plain, 165, key, "key");
        CHECK(!plain.verified && !plain.verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 735) {
        static const char prefix[] = "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJhcGkubGl2ZXN0b3JtLmNvIiwianRpIjoi";
        char key[244], input[280];
        CHECK(sizeof(prefix) - 1 == 65);
        memcpy(key, prefix, 65); test_secret(key + 65, 134, 7);
        key[199] = '.'; test_secret(key + 200, 43, 9);
        snprintf(input, sizeof(input), "livestorm %s ", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 1);
        test_key_result(&results.items[0], 735, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 1000) {
        const char *key = "b7c9d2e5f6a8b3c4d1e0f2a4b6c8d1e3a5c7e9f1";
        char input[64]; snprintf(input, sizeof(input), "MeRaKi %s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 1 && results.items[0].extra_data && !json_object_object_length(results.items[0].extra_data));
        br_result plain = results.items[0]; plain.extra_data = NULL;
        test_key_result(&plain, 1000, key, "key");
        CHECK(!plain.verified && !plain.verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 120) {
        const char *token = entry->version == 1 ? "Z7VoIYJ0K4rFWLBfkhOsLAWX" : "ATATTb7C9d2E5f6G8h3J4k1m0n2p4q6r8s1t3u5v7w9x2=Z7VoIYJ0";
        char input[240], raw_v2[200];
        snprintf(input, sizeof(input), "jira %s\njira XKName@grum.com\njira X\xe2\x84\xaaName@grum.com", token);
        snprintf(raw_v2, sizeof(raw_v2), "xkname@grum.com:%s:api.atlassian.com", token);
        br_results results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 1);
        br_result *r = &results.items[0]; br_json *part = NULL;
        CHECK(r->detector_type == 120 && r->raw.len == strlen(token) && !memcmp(r->raw.data, token, r->raw.len));
        CHECK(r->raw_v2.len == strlen(raw_v2) && !memcmp(r->raw_v2.data, raw_v2, r->raw_v2.len));
        CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 3);
        CHECK(json_object_object_get_ex(r->secret_parts, "email", &part) && !strcmp(json_object_get_string(part), "xkname@grum.com"));
        CHECK(json_object_object_get_ex(r->secret_parts, "domain", &part) && !strcmp(json_object_get_string(part), "api.atlassian.com"));
        CHECK(json_object_object_get_ex(r->secret_parts, "token", &part) && !strcmp(json_object_get_string(part), token));
        CHECK(r->extra_data && json_object_object_length(r->extra_data) == 2);
        CHECK(json_object_object_get_ex(r->extra_data, "version", &part) && !strcmp(json_object_get_string(part), entry->version == 1 ? "1" : "2"));
        CHECK(json_object_object_get_ex(r->extra_data, "rotation_guide", &part));
        CHECK(!strcmp(json_object_get_string(part), "https://howtorotate.com/docs/tutorials/atlassian/"));
        CHECK(!r->verified && !r->verification_error && !r->redacted && !r->structured_data);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 901) {
        const char *url = "ldap://Z7p8q.invalid/dc=Briar";
        const char *username = "BriarName", *password = "B7q9Vp2r4N6m8T1z";
        char input[160], raw[128];
        snprintf(input, sizeof(input), "LDAP://Z7p8q.invalid/dc=Briar\nuser '%s'\npass '%s'", username, password);
        snprintf(raw, sizeof(raw), "%s\t%s\t%s", url, username, password);
        br_results results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 1);
        br_result *r = &results.items[0]; br_json *part = NULL;
        CHECK(r->detector_type == 901 && r->raw.len == strlen(raw) && !memcmp(r->raw.data, raw, r->raw.len));
        CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 3);
        CHECK(json_object_object_get_ex(r->secret_parts, "url", &part) && !strcmp(json_object_get_string(part), url));
        CHECK(json_object_object_get_ex(r->secret_parts, "username", &part) && !strcmp(json_object_get_string(part), username));
        CHECK(json_object_object_get_ex(r->secret_parts, "password", &part) && !strcmp(json_object_get_string(part), password));
        CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->verified && !r->verification_error && !r->extra_data);
        CHECK(!r->redacted && !r->structured_data);
        br_results_clear(&results);
        results = test_scan(detector, NULL, false, url, strlen(url)); CHECK(!results.len);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 668 || entry->type == 267 || entry->type == 437 || entry->type == 177) {
        char key[957], input[1100];
        if (entry->type == 668) {
            const size_t lengths[] = {36, 235, 32, 47, 162, 42, 40, 66, 59, 7, 220};
            size_t used = 0;
            for (size_t i = 0; i < sizeof(lengths) / sizeof(*lengths); ++i) {
                if (i) key[used++] = i < 3 ? '.' : '-';
                test_secret(key + used, lengths[i], (unsigned)i); used += lengths[i];
            }
            CHECK(used == entry->key_len);
        } else if (entry->type == 177) {
            memcpy(key, "lin_api_", 8); test_secret(key + 8, 40, 3);
        } else test_secret(key, entry->key_len, 7);
        snprintf(input, sizeof(input), "%s %s", entry->keyword, key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 1);
        test_key_result(&results.items[0], entry->type, key, "key");
        br_results_clear(&results);
        if (entry->type == 267) {
            snprintf(input, sizeof(input), "less %s", key);
            results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
            test_key_result(&results.items[0], entry->type, key, "key"); br_results_clear(&results);
        }
        return;
    }
    if (entry->type == 191 || entry->type == 841 || entry->type == 952) {
        char key[865], input[1000];
        if (entry->type == 191) {
            strcpy(key, "api-abcdefgh-abcd-4abc-abcd-abcdefghijkl");
            strcpy(input, key);
        } else if (entry->type == 841) {
            strcpy(key, "24203d9f149dd02d1d944ee799cfb57e");
            snprintf(input, sizeof(input), "lemlist %s", key);
        } else {
            memcpy(key, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9", 36);
            key[36] = '.';
            test_secret(key + 37, 314, 0);
            key[351] = '.';
            test_secret(key + 352, 512, 7);
            snprintf(input, sizeof(input), "lemonsqueezy %s", key);
        }
        br_results results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 1);
        br_result *r = &results.items[0]; br_json *part = NULL;
        CHECK(r->detector_type == entry->type && r->raw.len == strlen(key));
        CHECK(!memcmp(r->raw.data, key, r->raw.len));
        CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 1);
        CHECK(json_object_object_get_ex(r->secret_parts, "key", &part));
        CHECK(!strcmp(json_object_get_string(part), key));
        CHECK(!r->raw_v2.data && !r->raw_v2.len && !r->verified && !r->verification_error);
        CHECK(!r->redacted && !r->structured_data);
        if (entry->type == 191)
            CHECK(r->extra_data && json_object_object_length(r->extra_data) == 0);
        else CHECK(!r->extra_data);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 1028 || entry->type == 489 || entry->type == 991 || entry->type == 992) {
        char key[52], secret[33], input[200];
        if (entry->type == 1028) {
            strcpy(key, "lsv2_pt_0123456789abcdef0123456789abcdef_0123456789");
            strcpy(input, key);
        } else if (entry->type == 489) {
            test_secret(key, 32, 0);
            snprintf(input, sizeof(input), "languagelayer %s", key);
        } else if (entry->type == 991) {
            strcpy(key, "t-1234567890abcd");
            snprintf(input, sizeof(input), "lark %s", key);
        } else {
            strcpy(key, "cli_AbCdEfGh12345678"); test_secret(secret, 32, 3);
            snprintf(input, sizeof(input), "lark %s\nlark %s", key, secret);
        }
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        br_result *r = &results.items[0]; br_json *part = NULL;
        CHECK(r->detector_type == entry->type && r->raw.len == strlen(key) && !memcmp(r->raw.data, key, r->raw.len));
        CHECK(r->secret_parts && json_object_object_get_ex(r->secret_parts, "key", &part));
        CHECK(!strcmp(json_object_get_string(part), key));
        if (entry->type == 992) {
            CHECK(json_object_object_length(r->secret_parts) == 2 && r->raw_v2.len == strlen(key) + strlen(secret));
            CHECK(!memcmp(r->raw_v2.data, key, strlen(key)) && !memcmp(r->raw_v2.data + strlen(key), secret, strlen(secret)));
            CHECK(json_object_object_get_ex(r->secret_parts, "secret", &part) && !strcmp(json_object_get_string(part), secret));
        } else CHECK(json_object_object_length(r->secret_parts) == 1 && !r->raw_v2.data && !r->raw_v2.len);
        if (entry->type == 991) {
            CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1);
            CHECK(json_object_object_get_ex(r->extra_data, "token_type", &part));
            CHECK(!strcmp(json_object_get_string(part), "Tenant Access Token"));
        } else CHECK(!r->extra_data);
        CHECK(!r->verified && !r->verification_error && !r->redacted && !r->structured_data);
        br_results_clear(&results);
        if (entry->type == 992) {
            snprintf(input, sizeof(input), "lark %s", key);
            results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!results.len);
            br_results_clear(&results);
        }
        return;
    }
    if (entry->type == 186 || entry->type == 736 || entry->type == 272 || entry->type == 1021) {
        char key[89], secondary[89], input[300], missing[180];
        const char *second_name = NULL;
        const char *uuid = "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3";
        if (entry->type == 186) {
            test_secret(key, 56, 0); test_secret(secondary, 88, 11);
            second_name = "private_key";
            snprintf(input, sizeof(input), "kraken %s\nkraken %s ", key, secondary);
            snprintf(missing, sizeof(missing), "kraken %s ", key);
        } else if (entry->type == 736) {
            strcpy(key, "c19c2539c53367c726a5c04c"); strcpy(secondary, "Briar!7pw");
            second_name = "passphrase";
            snprintf(input, sizeof(input), "kucoin %s\nkucoin %s\nkucoin\t%s", secondary, uuid, key);
            snprintf(missing, sizeof(missing), "kucoin %s\nkucoin\t%s", secondary, key);
        } else if (entry->type == 1021) {
            snprintf(key, sizeof(key), "sk-lf-%s", uuid);
            snprintf(secondary, sizeof(secondary), "pk-lf-%s", uuid);
            snprintf(input, sizeof(input), "langfuse %s\nlangfuse %s", secondary, key);
            snprintf(missing, sizeof(missing), "langfuse %s", key);
        } else {
            test_secret(key, 36, 0);
            for (size_t i = 0; i < 36; ++i) if (key[i] >= 'A' && key[i] <= 'Z') key[i] += 'a' - 'A';
            key[0] = 'g'; key[17] = '-';
            snprintf(input, sizeof(input), "kylas %s", key);
        }
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        if (second_name) {
            br_result *r = &results.items[0]; br_json *part = NULL;
            size_t klen = strlen(key), slen = strlen(secondary);
            CHECK(r->raw.len == klen && !memcmp(r->raw.data, key, klen));
            CHECK(r->raw_v2.len == klen + slen && !memcmp(r->raw_v2.data, key, klen));
            CHECK(!memcmp(r->raw_v2.data + klen, secondary, slen));
            CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
            CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
            CHECK(json_object_object_get_ex(r->secret_parts, second_name, &part) && !strcmp(json_object_get_string(part), secondary));
            CHECK(!r->redacted && !r->extra_data && !r->structured_data);
        } else test_key_result(&results.items[0], entry->type, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        if (entry->type != 272) {
            results = test_scan(detector, NULL, false, missing, strlen(missing)); CHECK(!results.len);
            br_results_clear(&results);
        }
        return;
    }
    if (entry->type == 935 || entry->type == 328 || entry->type == 656 || entry->type == 111) {
        char key[300], input[450];
        const char *env = "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3";
        if (entry->type == 328) {
            snprintf(key, sizeof(key), "ey%030u.ey%0200u.%040u", 7u, 8u, 9u);
            CHECK(strlen(key) == 276);
            snprintf(input, sizeof(input), "env %s\nkontent %s", env, key);
        } else if (entry->type == 935) {
            memcpy(key, "pk_", 3);
            for (size_t i = 0; i < 34; ++i) key[i + 3] = "0123456789abcdef"[(i * 7 + 3) % 16];
            key[37] = '\0'; strcpy(input, key);
        } else {
            test_secret(key, entry->type == 656 ? 43 : 25, 0);
            snprintf(input, sizeof(input), "%s %s", entry->keyword, key);
        }
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        if (entry->type == 328) {
            CHECK(results.items[0].raw.len == 36 && !memcmp(results.items[0].raw.data, env, 36));
            CHECK(results.items[0].raw_v2.len == 36 + strlen(key));
            CHECK(!memcmp(results.items[0].raw_v2.data, env, 36) && !memcmp(results.items[0].raw_v2.data + 36, key, strlen(key)));
            br_json *part = NULL;
            CHECK(json_object_object_length(results.items[0].secret_parts) == 2);
            CHECK(json_object_object_get_ex(results.items[0].secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
            CHECK(json_object_object_get_ex(results.items[0].secret_parts, "env_id", &part) && !strcmp(json_object_get_string(part), env));
        } else test_key_result(&results.items[0], entry->type, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 740 || entry->type == 760) {
        char key[41], input[80];
        size_t len = entry->type == 740 ? 40 : 32;
        const char *alphabet = entry->type == 740 ? "0123456789abcdef" : "0123456789abcdefghijklmnopqrstuvwxyz";
        size_t base = strlen(alphabet);
        for (size_t i = 0; i < len; ++i) key[i] = alphabet[(i * 7 + 3) % base];
        key[len] = '\0';
        snprintf(input, sizeof(input), "%s %s", entry->keyword, key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], entry->type, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 853 || entry->type == 296 || entry->type == 140 || entry->type == 573) {
        char key[66], input[180];
        size_t len = entry->type == 853 ? 12 : entry->type == 296 ? 20 : entry->type == 140 ? 64 : 65;
        test_secret(key, len, 0);
        if (entry->type == 853 || entry->type == 140)
            for (size_t i = 0; i < len; ++i) if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
        if (entry->type == 573) key[0] = '_';
        snprintf(input, sizeof(input), "%s %s", entry->keyword, key);
        if (entry->type == 140) {
            br_results missing = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!missing.len);
            br_results_clear(&missing);
            strcat(input, "\nkeen g7h9j2k5l6m8n3p4q1r0s2t4");
        }
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], entry->type, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 982 || entry->type == 786 || entry->type == 145 || entry->type == 105 || entry->type == 106) {
        char key[89], input[160];
        size_t len = entry->type == 982 ? 76 : entry->type == 786 ? 40 : entry->type == 105 ? 88 : 32;
        test_secret(key, len, 0);
        if (entry->type == 105) key[87] = '=';
        if (entry->type == 145)
            for (size_t i = 0; i < len; ++i) if (key[i] >= 'A' && key[i] <= 'Z') key[i] += 'a' - 'A';
        snprintf(input, sizeof(input), "%s %s", entry->keyword, key);
        if (entry->type == 786) {
            br_results missing = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!missing.len);
            br_results_clear(&missing);
            strcat(input, "\nUser@Example.test");
        }
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], entry->type, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 686) {
        char key[13], input[80]; test_secret(key, 12, 0);
        for (size_t i = 0; i < 12; ++i) if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
        snprintf(input, sizeof(input), "kanban %s\ntenant7.kanbantool.com", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 686, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        snprintf(input, sizeof(input), "kanban %s", key);
        results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(!results.len);
        br_results_clear(&results); return;
    }
    if (entry->type == 133 || entry->type == 715 || entry->type == 450 || entry->type == 510) {
        char key[37] = {0}, input[80];
        if (entry->type == 450) { memcpy(key, "pk.", 3); test_secret(key + 3, 32, 0); }
        else if (entry->type == 510) strcpy(key, "b7c9d2e5-f6a8-b3c4-d1e0-f2a4b6c8d1e3");
        else {
            for (size_t i = 0; i < 32; ++i) key[i] = "0123456789abcdef"[i % 16];
            if (entry->type == 133) key[0] = 'A';
        }
        snprintf(input, sizeof(input), "%s %s", entry->keyword, key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], entry->type, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 987) {
        char secret[74] = "s-s4t2ud-", id[74] = "u-s4t2af-", input[160];
        for (size_t i = 0; i < 64; ++i) { secret[9 + i] = "0123456789abcdef"[i % 16]; id[9 + i] = "fedcba9876543210"[i % 16]; }
        secret[73] = id[73] = '\0'; snprintf(input, sizeof(input), "%s %s", secret, id);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 987, secret, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 689) {
        char key[21], input[80]; test_secret(key, 20, 0);
        snprintf(input, sizeof(input), "invoiceocean %s\nhidden.invoiceocean.com", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 689, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 941) {
        char id[41], secret[129], input[210]; test_secret(id, 40, 0); test_secret(secret, 128, 7);
        snprintf(input, sizeof(input), "instamojo %s\ninstamojo %s", secret, id);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 941, id, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 156) {
        const char *key = "dG9rOgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJic=";
        char input[80]; snprintf(input, sizeof(input), "intercom %s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 156, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 813) {
        char key[36] = "sk_", input[60]; test_secret(key + 3, 32, 0);
        snprintf(input, sizeof(input), "iexapis %s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 813, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 459) {
        char account[28], key[55], input[130]; test_secret(account, 27, 0); test_secret(key, 54, 7);
        snprintf(input, sizeof(input), "hypertrack %s\nhypertrack %s", account, key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 459, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 107) {
        const char *uuid = "AbCdEf01-gHi2-JkL3-mNo4-PqRsTuVwXyZ5";
        char key[45], input[100];
        snprintf(key, sizeof(key), "%s%s", entry->version == 2 ? "pat-na1-" : "", uuid);
        snprintf(input, sizeof(input), entry->version == 1 ? "hapi_key %s" : "%s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        br_result plain = results.items[0]; plain.redacted = NULL;
        test_key_result(&plain, 107, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        if (entry->version == 2) {
            char redacted[40]; snprintf(redacted, sizeof(redacted), "%s...", key + 8);
            CHECK(results.items[0].redacted && !strcmp(results.items[0].redacted, redacted));
        } else CHECK(!results.items[0].redacted);
        br_results_clear(&results); return;
    }
    if (entry->type == 926) {
        char key[38] = "hf_"; test_secret(key + 3, 34, 0);
        br_results results = test_scan(detector, NULL, false, key, 37); CHECK(results.len == 1);
        test_key_result(&results.items[0], 926, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 764) {
        char key[65], input[100];
        for (size_t i = 0; i < 64; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[64] = '\0'; snprintf(input, sizeof(input), "holistic %s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 764, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 19) {
        char key[66], input[100];
        if (entry->version == 1) strcpy(key, "A1b2c3d4-1234-abcd-5678-012345abcdef");
        else { memcpy(key, "HRKU-AA", 7); test_secret(key + 7, 58, 0); }
        snprintf(input, sizeof(input), entry->version == 1 ? "heroku %s" : "%s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 19, key, "key");
        CHECK(!results.items[0].extra_data && !results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 571) {
        char id[18], hidden[33], input[100]; test_secret(id, 17, 0); test_secret(hidden, 32, 7);
        snprintf(input, sizeof(input), "hive %s\nhive %s", id, hidden);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 571, id, "key");
        CHECK(!results.items[0].extra_data && !results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 1030) {
        char key[65], input[160], raw_v2[160]; test_secret(key, 64, 0);
        const char *domain = "Registry101.hasura.app";
        snprintf(input, sizeof(input), "hasura %s\n%s", key, domain);
        snprintf(raw_v2, sizeof(raw_v2), "%s:%s", domain, key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *r = &results.items[0]; br_json *part = NULL;
        CHECK(r->detector_type == 1030 && r->raw.len == 64 && !memcmp(r->raw.data, key, 64));
        CHECK(r->raw_v2.len == strlen(raw_v2) && !memcmp(r->raw_v2.data, raw_v2, strlen(raw_v2)));
        CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
        CHECK(json_object_object_get_ex(r->secret_parts, "domain", &part) && !strcmp(json_object_get_string(part), domain));
        CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
        CHECK(!r->redacted && !r->extra_data && !r->verified && !r->verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 1020) {
        char key[73] = "pat.", input[100];
        test_secret(key + 4, 22, 0); key[26] = '.';
        memcpy(key + 27, "a19b28c37d46e50fa19b28c3", 24); key[51] = '.'; test_secret(key + 52, 20, 7);
        snprintf(input, sizeof(input), "harness %s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 1020, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 260) {
        char key[98], input[160]; test_secret(key, 97, 0); key[20] = '.'; key[40] = '_';
        snprintf(input, sizeof(input), "harvest %s\nharvest 0012", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 260, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results); return;
    }
    if (entry->type == 1061 || entry->type == 1062) {
        char key[125], input[220], raw_v2[220];
        const char *url = "https://registry.hashicorp.cloud";
        memcpy(key, entry->type == 1061 ? "hvb." : "hvs.", 4); test_secret(key + 4, entry->key_len - 4, 0);
        snprintf(input, sizeof(input), "%s\n%s/path", key, url);
        snprintf(raw_v2, sizeof(raw_v2), "%s:%s", key, url);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *r = &results.items[0]; br_json *part = NULL;
        CHECK(r->detector_type == entry->type && r->raw.len == entry->key_len && !memcmp(r->raw.data, key, entry->key_len));
        CHECK(r->raw_v2.len == strlen(raw_v2) && !memcmp(r->raw_v2.data, raw_v2, strlen(raw_v2)));
        CHECK(r->redacted && strlen(r->redacted) == 11 && !memcmp(r->redacted, key, 8) && !strcmp(r->redacted + 8, "..."));
        CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
        CHECK(json_object_object_get_ex(r->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
        CHECK(json_object_object_get_ex(r->secret_parts, "url", &part) && !strcmp(json_object_get_string(part), url));
        CHECK(!r->verified && !r->verification_error && !r->extra_data && !r->structured_data);
        br_results_clear(&results); return;
    }
    if (entry->type == 1036) {
        const char *role = "01234567-89ab-cdef-0123-456789abcdef";
        const char *secret = "ABCDEF01-2345-6789-abcd-ef0123456789";
        const char *url = "https://registry.hashicorp.cloud/path";
        char input[256], raw_v2[74];
        snprintf(input, sizeof(input), "role %s\n%64s\nsecret %s\n%s", role, "", secret, url);
        snprintf(raw_v2, sizeof(raw_v2), "%s:%s", role, secret);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *r = &results.items[0]; br_json *part = NULL;
        CHECK(r->detector_type == 1036 && r->raw.len == 36 && !memcmp(r->raw.data, secret, 36));
        CHECK(r->raw_v2.len == 73 && !memcmp(r->raw_v2.data, raw_v2, 73));
        CHECK(r->secret_parts && json_object_object_length(r->secret_parts) == 2);
        CHECK(json_object_object_get_ex(r->secret_parts, "role_id", &part) && !strcmp(json_object_get_string(part), role));
        CHECK(json_object_object_get_ex(r->secret_parts, "secret_id", &part) && !strcmp(json_object_get_string(part), secret));
        CHECK(r->extra_data && json_object_object_length(r->extra_data) == 1);
        CHECK(json_object_object_get_ex(r->extra_data, "URL", &part) && !strcmp(json_object_get_string(part), url));
        CHECK(!r->verified && !r->verification_error && !r->redacted && !r->structured_data);
        br_results_clear(&results); return;
    }
    if (entry->type == 570) {
        const char *username = "AbC@de.fg";
        const char *input = "guru AbC@de.fg\nguru ghijklmn-opqr-stuv-wxyz-0123456789ab";
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 570, username, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 988) {
        char key[57] = "gsk_"; test_secret(key + 4, 52, 0);
        br_results results = test_scan(detector, NULL, false, key, 56); CHECK(results.len == 1);
        br_result plain = results.items[0]; plain.extra_data = NULL;
        test_key_result(&plain, 988, key, "key");
        br_json *guide = NULL;
        CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 1);
        CHECK(json_object_object_get_ex(results.items[0].extra_data, "rotation_guide", &guide) &&
              !strcmp(json_object_get_string(guide), "https://howtorotate.com/docs/tutorials/groq/"));
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 223) {
        char key[1128] = "ey", id[26], input[1200];
        test_secret(key + 2, 73, 0); key[75] = '!'; memcpy(key + 76, "ey", 2);
        test_secret(key + 78, 365, 7); key[443] = '?'; test_secret(key + 444, 683, 11);
        test_secret(id, 25, 3); snprintf(input, sizeof(input), "%s\ngraph %s", key, id);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 223, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 963) {
        char key[47] = "glsa_", input[100], raw_v2[100];
        const char *domain = "Tenant97.grafana.net";
        test_secret(key + 5, 41, 0); key[20] = '_';
        snprintf(input, sizeof(input), "%s\n%s", key, domain);
        snprintf(raw_v2, sizeof(raw_v2), "%s:%s", domain, key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 963 && result->raw.len == 46 && !memcmp(result->raw.data, key, 46));
        CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, strlen(raw_v2)));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->extra_data && !result->structured_data);
        br_json *part = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "domain", &part) && !strcmp(json_object_get_string(part), domain));
        CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 830) {
        char key[68] = "glc_eyJ"; test_secret(key + 7, 60, 0); key[20] = '+'; key[40] = '/';
        br_results results = test_scan(detector, NULL, false, key, 67); CHECK(results.len == 1);
        test_key_result(&results.items[0], 830, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 1008) {
        char key[38], secret[23], input[100];
        test_secret(key, entry->key_len, 0); key[17] = '_'; test_secret(secret, 22, 7);
        snprintf(input, sizeof(input), "godaddy %s\ngodaddy %s", key, secret);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        br_result plain = results.items[0]; plain.extra_data = NULL;
        test_key_result(&plain, 1008, key, "key");
        CHECK(results.items[0].extra_data && json_object_object_length(results.items[0].extra_data) == 0);
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 1041) {
        char key[40] = "AIzaSy"; test_secret(key + 6, 33, 0); key[38] = '-';
        br_results results = test_scan(detector, NULL, false, key, 39); CHECK(results.len == 1);
        br_result plain = results.items[0]; plain.redacted = NULL;
        test_key_result(&plain, 1041, key, "key");
        CHECK(results.items[0].redacted && strlen(results.items[0].redacted) == 11 &&
              !memcmp(results.items[0].redacted, key, 8) && !strcmp(results.items[0].redacted + 8, "..."));
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 714) {
        char key[45], input[120]; test_secret(key, 43, 0); key[43] = '='; key[44] = '\0';
        snprintf(input, sizeof(input), "gocanvas Mailbox@fixture.invalid\ngocanvas %s \n", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        test_key_result(&results.items[0], 714, key, "key");
        CHECK(!results.items[0].verified && !results.items[0].verification_error);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 9) {
        const char *key = entry->version == 1 ? "Ab3dE5fGh7Jk9LmNoP2q" : entry->version == 2 ? "glpat-Ab3dE5fGh7Jk9LmNoP2q" : "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ0.a2.abcdefgh9";
        const char *cloud = "https://gitlab.com";
        char input[100], raw_v2[100]; snprintf(input, sizeof(input), entry->version == 1 ? "gitlab %s" : "%s", key);
        snprintf(raw_v2, sizeof(raw_v2), "%s%s", key, cloud);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 9 && result->raw.len == strlen(key) && !memcmp(result->raw.data, key, result->raw.len));
        CHECK(result->raw_v2.len == strlen(raw_v2) && !memcmp(result->raw_v2.data, raw_v2, result->raw_v2.len));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->structured_data && !result->primary_secret.data && !result->verification_from_cache);
        br_json *field = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "key", &field) && !strcmp(json_object_get_string(field), key));
        CHECK(json_object_object_get_ex(result->secret_parts, "host", &field) && !strcmp(json_object_get_string(field), cloud));
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 2);
        CHECK(json_object_object_get_ex(result->extra_data, "version", &field) && !strcmp(json_object_get_string(field), entry->version == 1 ? "1" : entry->version == 2 ? "2" : "3"));
        CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &field) && !strcmp(json_object_get_string(field), "https://howtorotate.com/docs/tutorials/gitlab/"));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 36) {
        const char *key = "-----BEGIN RSA PRIVATE KEY-----\nQ7r2T9\n-----END RSA PRIVATE KEY-----";
        char input[160]; snprintf(input, sizeof(input), "github 012345\ngithub 654321\ngithub %s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 2);
        for (size_t i = 0; i < results.len; ++i) {
            const br_result *result = &results.items[i];
            CHECK(result->detector_type == 36 && result->raw.len == strlen(key) && !memcmp(result->raw.data, key, result->raw.len));
            CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->verified && !result->verification_error);
            CHECK(!result->redacted && !result->structured_data && !result->primary_secret.data && !result->verification_from_cache);
            br_json *field = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
            CHECK(json_object_object_get_ex(result->secret_parts, "key", &field) && !strcmp(json_object_get_string(field), key));
            CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
            CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &field) && !strcmp(json_object_get_string(field), "https://howtorotate.com/docs/tutorials/github/"));
        }
        CHECK(results.items[0].raw.data != results.items[1].raw.data && results.items[0].secret_parts != results.items[1].secret_parts);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 1050) {
        char id[65], secret[71], input[180], raw_v2[153];
        const char *hex = "0123456789abcdef", *cloud = "https://gitlab.com";
        snprintf(id, sizeof(id), "%s%s%s%s", hex, hex, hex, hex);
        snprintf(secret, sizeof(secret), "gloas-%s%s%s%s", hex, hex, hex, hex);
        snprintf(input, sizeof(input), "client_id %s\n%s", id, secret);
        snprintf(raw_v2, sizeof(raw_v2), "%s%s%s", id, secret, cloud);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 1050 && result->raw.len == 70 && !memcmp(result->raw.data, secret, 70));
        CHECK(result->raw_v2.len == 152 && !memcmp(result->raw_v2.data, raw_v2, 152));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->extra_data && !result->structured_data && !result->primary_secret.data && !result->verification_from_cache);
        br_json *field = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 3);
        CHECK(json_object_object_get_ex(result->secret_parts, "client_id", &field) && !strcmp(json_object_get_string(field), id));
        CHECK(json_object_object_get_ex(result->secret_parts, "client_secret", &field) && !strcmp(json_object_get_string(field), secret));
        CHECK(json_object_object_get_ex(result->secret_parts, "endpoint", &field) && !strcmp(json_object_get_string(field), cloud));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 924) {
        const char *id = "A1b2C3d4E5f6G7h8I9j0", *secret = "b7c9d2e5f6b8c3d4e1f0a2c4e6b8f1d3a5c7e9b2";
        char input[100], raw_v2[61]; snprintf(input, sizeof(input), "github %s\ngithub %s", id, secret);
        snprintf(raw_v2, sizeof(raw_v2), "%s%s", id, secret);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 924 && result->raw.len == 20 && !memcmp(result->raw.data, id, 20));
        CHECK(result->raw_v2.len == 60 && !memcmp(result->raw_v2.data, raw_v2, 60));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->structured_data && !result->primary_secret.data && !result->verification_from_cache);
        br_json *field = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "id", &field) && !strcmp(json_object_get_string(field), id));
        CHECK(json_object_object_get_ex(result->secret_parts, "secret", &field) && !strcmp(json_object_get_string(field), secret));
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &field) && !strcmp(json_object_get_string(field), "https://howtorotate.com/docs/tutorials/github/"));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 8) {
        const char *key = entry->version == 1 ? "0123456789abcdef0123456789abcdef01234567" : "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        char input[100]; snprintf(input, sizeof(input), entry->version == 1 ? "github_token %s" : "%s", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 8 && result->raw.len == 40 && !memcmp(result->raw.data, key, 40));
        CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->verified && !result->verification_error);
        CHECK(!result->redacted && !result->structured_data && !result->primary_secret.data && !result->verification_from_cache);
        CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
        br_json *field = NULL; CHECK(json_object_object_get_ex(result->secret_parts, "key", &field) && !strcmp(json_object_get_string(field), key));
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == (entry->version == 1 ? 2 : 3));
        CHECK(json_object_object_get_ex(result->extra_data, "version", &field) && !strcmp(json_object_get_string(field), entry->version == 1 ? "1" : "2"));
        CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &field) && !strcmp(json_object_get_string(field), "https://howtorotate.com/docs/tutorials/github/"));
        if (entry->version == 2) CHECK(json_object_object_get_ex(result->extra_data, "token_type", &field) && !strcmp(json_object_get_string(field), "Personal Access Token (classic)"));
        br_results_clear(&results);
        return;
    }
    if (entry->type == 327 || entry->type == 633) {
        char key[41], id[19], input[160]; test_secret(key, entry->key_len, 0); test_secret(id, 18, 7);
        snprintf(input, sizeof(input), "%s %s\n%s %s\n%s %s", entry->keyword, key, entry->keyword, id, entry->keyword, id);
        br_results results = test_scan(detector, NULL, false, input, strlen(input));
        CHECK(results.len == 2); /* Hidden ID occurrences remain a full product. */
        for (size_t i = 0; i < 2; ++i) {
            test_key_result(&results.items[i], entry->type, key, "key");
            CHECK(!results.items[i].verified && !results.items[i].verification_error);
        }
        CHECK(results.items[0].raw.data != results.items[1].raw.data &&
              results.items[0].secret_parts != results.items[1].secret_parts);
        br_results_clear(&results);
        return;
    }
    if (entry->type == 407) {
        char key[40], input[80]; test_secret(key, 39, 0);
        snprintf(input, sizeof(input), "geocod %s\ngeocod AbCdEfG", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 407 && result->raw.len == 39 && !memcmp(result->raw.data, key, 39));
        CHECK(result->raw_v2.len == 46 && !memcmp(result->raw_v2.data, key, 39) && !memcmp(result->raw_v2.data + 39, "AbCdEfG", 7));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
        CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set);
        br_json *part = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
        CHECK(json_object_object_get_ex(result->secret_parts, "search_engine", &part) && !strcmp(json_object_get_string(part), "AbCdEfG"));
        br_results_clear(&results); return;
    }
    if (entry->type == 876) {
        char key[28] = "master-", secret[28], input[70]; test_secret(key + 7, 20, 0); test_secret(secret, 27, 9);
        snprintf(input, sizeof(input), "%s %s", key, secret);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 876 && result->raw.len == 27 && !memcmp(result->raw.data, key, 27));
        CHECK(result->raw_v2.len == 54 && !memcmp(result->raw_v2.data, key, 27) && !memcmp(result->raw_v2.data + 27, secret, 27));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
        CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set);
        br_json *part = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
        CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part) && !strcmp(json_object_get_string(part), secret));
        br_results_clear(&results); return;
    }
    if (entry->type == 426) {
        char key[65], input[80]; test_secret(key, 64, 0);
        snprintf(input, sizeof(input), "gengo%s\n", key);
        br_results results = test_scan(detector, NULL, false, input, strlen(input)); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 426 && result->raw.len == 64 && !memcmp(result->raw.data, key, 64));
        CHECK(result->raw_v2.len == 128 && !memcmp(result->raw_v2.data, key, 64) && !memcmp(result->raw_v2.data + 64, key, 64));
        CHECK(!result->verified && !result->verification_error && !result->redacted && !result->extra_data && !result->structured_data && !result->verification_from_cache);
        CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set);
        br_json *part = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), key));
        CHECK(json_object_object_get_ex(result->secret_parts, "secret", &part) && !strcmp(json_object_get_string(part), key));
        br_results_clear(&results); return;
    }
    if (entry->type == 983) {
        static const char input[] = "{\"client_id\":\"42.hidden.apps.googleusercontent.com\",\"client_secret\":\"offline\",\"refresh_token\":\"abcdef\",\"type\":\"authorized_user\"}";
        br_results results = test_scan(detector, NULL, false, input, sizeof(input) - 1); CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 983 && result->raw.len == entry->key_len && !memcmp(result->raw.data, "42", 2));
        CHECK(result->raw_v2.len == 8 && !memcmp(result->raw_v2.data, "42abcdef", 8));
        CHECK(result->redacted && !strcmp(result->redacted, "abc...f") && !result->extra_data && !result->structured_data);
        CHECK(!result->verified && !result->verification_error && !result->verification_from_cache);
        CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set);
        br_json *part = NULL; CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 2);
        CHECK(json_object_object_get_ex(result->secret_parts, "client_id", &part) && !strcmp(json_object_get_string(part), "42"));
        CHECK(json_object_object_get_ex(result->secret_parts, "refresh_token", &part) && !strcmp(json_object_get_string(part), "abcdef"));
        br_results_clear(&results); return;
    }
    if (entry->type == 6) {
        static const char input[] = "{\"client_email\":\"briar87@offline.invalid\",\"auth_provider_x509_cert_url\":\"unused\"}";
        br_results results = test_scan(detector, NULL, false, input, sizeof(input) - 1);
        CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 6 && result->raw.len == entry->key_len && !memcmp(result->raw.data, "briar87@offline.invalid", result->raw.len));
        CHECK(result->redacted && !strcmp(result->redacted, "briar87@offline.invalid") && result->raw_v2.len);
        CHECK(!result->verified && !result->verification_error && !result->verification_from_cache && !result->structured_data);
        CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set);
        br_json *part = NULL;
        CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
        CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && (size_t)json_object_get_string_len(part) == result->raw_v2.len && !memcmp(json_object_get_string(part), result->raw_v2.data, result->raw_v2.len));
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 2);
        br_results_clear(&results); return;
    }
    if (entry->type == 899) {
        static const char input[] = "ftp://Briar86:Z8k2Q7s9@fixture.invalid/path";
        static const char raw[] = "ftp://Briar86:Z8k2Q7s9@fixture.invalid";
        br_results results = test_scan(detector, NULL, false, input, sizeof(input) - 1);
        CHECK(results.len == 1);
        const br_result *result = &results.items[0];
        CHECK(result->detector_type == 899 && result->raw.len == entry->key_len);
        CHECK(result->raw.len == sizeof(raw) - 1 && !memcmp(result->raw.data, raw, sizeof(raw) - 1));
        CHECK(result->redacted && !strcmp(result->redacted, "ftp://Briar86:********@fixture.invalid"));
        CHECK(!result->raw_v2.data && !result->raw_v2.len && !result->extra_data && !result->structured_data);
        CHECK(!result->verified && !result->verification_error && !result->verification_from_cache);
        CHECK(!result->primary_secret.data && !result->primary_secret.len && !result->primary_line && !result->chunk_offset_set);
        br_json *part = NULL;
        CHECK(result->secret_parts && json_object_object_length(result->secret_parts) == 1);
        CHECK(json_object_object_get_ex(result->secret_parts, "key", &part) && !strcmp(json_object_get_string(part), raw));
        br_results_clear(&results);
        return;
    }
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
    if (entry->type == 763 || entry->type == 939)
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
    if (entry->type == 349 || entry->type == 856) key[15] = '=';
    if (entry->type == 509) key[15] = '_';
    if (entry->type == 271) key[15] = '-';
    if (entry->type == 259) strcpy(key, "A7z9w2y5-g6h8-j3k4-m1n0-p2q4r6s8t1u3");
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
    if (entry->type == 112) { key[35] = '-'; key[66] = '_'; }
    if (entry->type == 283) { key[3] = 'A'; key[11] = '-'; }
    if (entry->type == 284) strcpy(key, "Aa0f-b1c2-d3e4f5-a6b7c8-d9e0f1a2");
    if (entry->type == 379) key[9] = 'z';
    if (entry->type == 784) key[14] = '-';
    if (entry->type == 771) { key[9] = '_'; key[18] = '-'; }
    if (entry->type == 636) { key[8] = '-'; key[9] = 'z'; }
    if (entry->type == 416) { key[6] = '_'; key[17] = '-'; }
    if (entry->type == 68) { key[7] = '_'; key[19] = '-'; }
    if (entry->type == 527) { key[8] = '.'; key[21] = '-'; }
    if (entry->type == 592) key[15] = '.';
    if (entry->type == 381) { key[4] = '_'; key[8] = '-'; key[15] = '='; }
    if (entry->type == 394) { if (entry->version == 1) key[8] = '-'; else memcpy(key, "na1.", 4); key[10] = '+'; key[36] = '/'; }
    if (entry->type == 428) memcpy(key, "flb_live_", 9);
    if (entry->type == 427) { key[36] = '!'; key[80] = '.'; key[120] = '_'; key[190] = '-'; }
    if (entry->type == 199) memcpy(key, "fio-u-", 6);
    if (entry->type == 1009) { memcpy(key, "shltm_", 6); key[16] = '_'; key[30] = key[45] = '-'; }
    if (entry->type == 848) { memcpy(key, entry->keyword, 36); memcpy(key + 36, ".ey", 3); key[40] = '.'; }
    if (entry->type == 173) { memcpy(key, "FLWSECK-", 8); memcpy(key + 40, "-X", 2); }
    if (entry->type == 249) { memcpy(key, "0123456789abcdef", 16); key[24] = '+'; key[33] = '/'; key[59] = '='; }
    if (entry->type == 980) memcpy(key, "FlyV1 fm1_", 10);
    if (entry->type == 713) { key[16] = '+'; key[33] = '.'; key[50] = '_'; key[62] = '-'; }
    if (entry->type == 712) {
        memcpy(key, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", 36);
        key[36] = key[287] = '.'; key[300] = '_'; key[319] = '-';
    }
    if (entry->type == 667) key[8] = key[13] = key[18] = key[23] = '-';
    if (entry->type == 423) {
        memcpy(key, "API_KEY", 7);
        for (size_t i = 7; i < entry->key_len; ++i) if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
    }
    if (entry->type == 808) {
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[8] = '.';
    }
    if (entry->type == 113) {
        if (entry->version == 1) strcpy(key, "730194-ghijklmn-opqr-stuv-wxyz-0123456789az");
        else if (entry->version == 2) { memcpy(key, "fig|_", 5); key[17] = '_'; key[30] = '-'; }
        else { memcpy(key, "figp_", 5); key[20] = '-'; key[57] = key[58] = '='; }
    }
    if (entry->type == 994) {
        if (entry->version == 1)
            for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789ABCDEF"[i % 16];
        else {
            memcpy(key, "sk_", 3);
            for (size_t i = 3; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[(i - 3) % 16];
        }
    }
    if (entry->type == 993) { memcpy(key, "endr+", 5); key[11] = '-'; }
    if (entry->type == 258 || entry->type == 905 || entry->type == 962 || entry->type == 527 || entry->type == 454 || entry->type == 940)
        for (size_t i = 0; i < entry->key_len; ++i)
            if (key[i] >= 'a' && key[i] <= 'z') key[i] -= 'a' - 'A';
    if (entry->type == 325) strcpy(key, "apiuser-a1b2c3d4e5f6@apiconnector.com");
    if (entry->type == 919 || entry->type == 821 || entry->type == 858) {
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = "0123456789abcdef"[i % 16];
        key[8] = key[13] = key[18] = key[23] = '-';
    }
    if (entry->type == 66) {
        char secret[69]; test_secret(secret, 68, 11);
        snprintf(key, sizeof(key), "https://discord.com/api/webhooks/123456789012345678/%s", secret);
    }
    if (entry->type == 838 || entry->type == 360)
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
    case 69:
        memcpy(key, "ya29.", 5);
        break;
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
    case 40: case 65: secondary = "12345678901234567"; secondary_name = "id"; break;
    case 416: case 454: secondary = key; secondary_name = "secret"; break;
    case 771:
        test_secret(secondary_buffer, 36, 11); secondary_buffer[12] = '-';
        secondary = secondary_buffer; secondary_name = "id"; break;
    case 281: secondary = "G7h9K2m4-N6p8-Q1r3-S5t7-U9v1W3x5Y7z9"; secondary_name = "id"; break;
    case 921: secondary = "briar7"; secondary_name = "username"; break;
    case 325: secondary = "AbCd1234"; secondary_name = "password"; break;
    case 639: secondary = "u7b9r@m4c8p.k2"; secondary_name = "email"; break;
    case 424: case 642: secondary = "z7m9q2r4"; secondary_name = "id"; break;
    case 265: secondary = "WorkONE"; secondary_name = "account"; break;
    case 652:
        test_secret(secondary_buffer, 24, 11);
        secondary = secondary_buffer; secondary_name = "id";
        break;
    case 993:
        memcpy(secondary_buffer, key, entry->key_len + 1); secondary_buffer[5] = 'Q';
        secondary = secondary_buffer; secondary_name = "secret";
        break;
    case 727:
        test_secret(secondary_buffer, 30, 11); secondary_buffer[8] = '_';
        secondary = secondary_buffer; secondary_name = "id";
        break;
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
    case 261:
        /* UUID-shape with the source capital-A first group only. */
        test_secret(key, 36, 0);
        key['0'] = 'A'; key[8] = key[13] = key[18] = key[23] = '-';
        for (size_t i = 0; i < 36; ++i) if (i != 8 && i != 13 && i != 18 && i != 23 && key[i] > 'f') key[i] = 'a';
        break;
    case 157:
        /* Seven-uppercase-alphanumeric groups joined by three literal hyphens. */
        for (size_t i = 0; i < entry->key_len; ++i) key[i] = (i % 8 == 7) ? '-' : 'A';
        break;
    case 669:
        /* Exactly 36.115.43 lowercase-alnum segments, separated by literal dots. */
        test_secret(key, 196, 0);
        key[36] = '.';
        key[152] = '.';
        break;
    case 820:
        for (size_t i = 0; i < 40; ++i) key[i] = "0123456789abcdef"[i % 16];
        break;
    case 246:
        /* JWT-shaped head/middle/signature with the required literal prefixes. */
        memcpy(key, "eyJ", 3);
        test_secret(key + 3, 20, 3);
        key[23] = '.';
        memcpy(key + 24, "eyJ", 3);
        test_secret(key + 27, 120, 5);
        key[147] = '.';
        test_secret(key + 148, 30, 9);
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
    case 184: case 749:
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
    else if (entry->type == 994 && entry->version == 1)
        snprintf(input, sizeof(input), "elevenlabs = '%s'", key);
    else if (secondary)
        snprintf(input, sizeof(input), "%s %s\n%s %s", entry->keyword, key, entry->keyword, secondary);
    else if (entry->type == 113 && entry->version == 3) snprintf(input, sizeof(input), "%s", key);
    else if (entry->type == 808) snprintf(input, sizeof(input), "fibery %s\nhttps://Briar79.fibery.io/", key);
    else if (entry->type == 839) snprintf(input, sizeof(input), "formsite %s\nformsite fs1\nformsite AbC123", key); /* Both required fields stay hidden. */
    else if (entry->type == 681) snprintf(input, sizeof(input), "freshbooks %s\nfreshbooks https://www.Briar85.com", key); /* Required URI stays hidden. */
    else if (entry->type == 682) snprintf(input, sizeof(input), "mite %s\nbriar-mite.mite.yo.lk", key);
    else if (entry->type == 678) snprintf(input, sizeof(input), "freshdesk %s\nbriar86.freshdesk.com", key); /* Direct required host stays hidden. */
    else if (entry->type == 390) snprintf(input, sizeof(input), "%s", key);
    else if (entry->type == 712 || entry->type == 184) snprintf(input, sizeof(input), "%s %s\n", entry->keyword, key); /* Required consumed suffix, absent from Raw. */
    else snprintf(input, sizeof(input), "%s %s", entry->keyword, key);

    br_results results = test_scan(detector, NULL, false, input, strlen(input));
    CHECK(results.len == (entry->type == 416 || entry->type == 454 ? 4u : entry->type == 42 || entry->type == 56 || entry->type == 386 || entry->type == 180 || entry->type == 282 || entry->type == 993 ? 2u : 1u));
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
    if (entry->type == 828 || entry->type == 711 || entry->type == 382 || entry->type == 863 || entry->type == 683 || entry->type == 821 || entry->type == 639 || entry->type == 652 || entry->type == 771 || entry->type == 808 || entry->type == 642 || entry->type == 265) {
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
    if (entry->type == 307 || entry->type == 196 || entry->type == 962) CHECK(result->extra_data && json_object_object_length(result->extra_data) == 0);
    if (entry->type == 40 || entry->type == 58 || entry->type == 65) CHECK(!result->extra_data && result->redacted && !strcmp(result->redacted, secondary));
    if (entry->type == 919) CHECK(!result->extra_data && result->redacted && !strcmp(result->redacted, key));
    if (entry->type == 100) CHECK(!result->extra_data && !result->redacted); /* No invented version metadata. */
    if (entry->type == 142) {
        if (entry->version == 1) CHECK(result->extra_data && json_object_object_length(result->extra_data) == 0);
        else CHECK(!result->extra_data);
    }
    if (entry->type == 4 || entry->type == 113 || entry->type == 430 || entry->type == 333 || entry->type == 394) {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, entry->type == 4 ? "Version" : "version", &part));
        CHECK(json_object_is_type(part, json_type_string));
        CHECK(!strcmp(json_object_get_string(part), entry->version == 1 ? "1" : entry->version == 2 ? "2" : "3"));
    }
    if (entry->type == 1009) {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &part));
        CHECK(!strcmp(json_object_get_string(part), "https://howtorotate.com/docs/tutorials/flexport/"));
        CHECK(!result->redacted);
    }
    if (entry->type == 990) {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == 1);
        CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &part));
        CHECK(!strcmp(json_object_get_string(part), "https://howtorotate.com/docs/tutorials/eraser/"));
        CHECK(!result->redacted);
    }
    if (entry->type == 994) {
        CHECK(result->extra_data && json_object_object_length(result->extra_data) == (entry->version == 1 ? 2 : 1));
        CHECK(json_object_object_get_ex(result->extra_data, "version", &part));
        CHECK(!strcmp(json_object_get_string(part), entry->version == 1 ? "1" : "2"));
        if (entry->version == 1) {
            CHECK(json_object_object_get_ex(result->extra_data, "rotation_guide", &part));
            CHECK(!strcmp(json_object_get_string(part), "https://howtorotate.com/docs/tutorials/elevenlabs/"));
        } else CHECK(!json_object_object_get_ex(result->extra_data, "rotation_guide", &part));
        CHECK(!result->redacted);
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
    const char *key_name = entry->type == 919 || entry->type == 180 ? "id" : entry->type == 325 ? "email" : entry->type == 921 ? "pat" : entry->type == 39 ? "app_key" : (entry->type == 1048 || entry->type == 1043) ? "api_key" : entry->type == 456 ? "url" : entry->type == 1003 ? "client_id" : (entry->type == 40 || entry->type == 512) ? "secret" : entry->type == 1025 ? "id" : (entry->type == 1018 || entry->type == 958) ? "password" : entry->type == 931 ? "account_key" : (entry->type == 957 || entry->type == 1019 || entry->type == 1024 || entry->type == 975) ? "url" : (entry->type == 2 || entry->type == 959) ? "access_key_id" : entry->type == 1045 ? "secret" :
                           entry->type == 1032 || entry->type == 55 ? "client_secret" :
                           entry->type == 113 || entry->type == 375 || entry->type == 1014 || entry->type == 1015 ||
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
        else if (entry->type == 40 || entry->type == 55 || entry->type == 1018 || entry->type == 512 || entry->type == 708 || entry->type == 739) snprintf(raw_v2, sizeof(raw_v2), "%s%s", secondary, key);
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
    feature_gate_tests(405, "EnigmaDetectorEnabled");
    feature_gate_tests(1053, "BraintrustDetectorEnabled");
    feature_gate_tests(1050, "GitLabOAuthDetectorEnabled");
    feature_gate_tests(1061, "HashiCorpVaultBatchTokenDetectorEnabled");
    feature_gate_tests(1062, "HashiCorpVaultTokenDetectorEnabled");
    feature_gate_tests(1059, "DuffelTokenDetectorEnabled");
    feature_gate_tests(1063, "DuoDetectorEnabled");
    feature_gate_tests(1048, "CloudinaryDetectorEnabled");
    feature_gate_tests(1043, "DatadogApiKeyDetectorEnabled");
    feature_gate_tests(939, "IPInfoDetectorEnabled");
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
        CHECK(detector->nkeywords == (entry->type == 931 ? 15u : entry->type == 7 ? 5u : (entry->type == 107 && entry->version == 1) ? 4u : entry->type == 196 || (entry->type == 8 && entry->version == 2) || (entry->type == 3 && entry->version == 1) ? 6u :
              entry->type == 994 || entry->type == 2 || entry->type == 120 || entry->type == 181 || entry->type == 1047 || entry->type == 897 || entry->type == 992 || (entry->type == 921 && entry->version == 2) ? 3u :
              entry->type == 987 || entry->type == 107 || entry->type == 926 || entry->type == 8 || entry->type == 876 || entry->type == 282 || entry->type == 360 || entry->type == 1059 || entry->type == 18 || entry->type == 39 || entry->type == 1043 || entry->type == 62 || entry->type == 343 || entry->type == 954 || entry->type == 189 || entry->type == 307 || entry->type == 907 || entry->type == 920 || entry->type == 170 || entry->type == 933 || entry->type == 1046 || entry->type == 971 || entry->type == 1013 || entry->type == 1018 || entry->type == 1029 || entry->type == 603 || entry->type == 975 || entry->type == 739 || entry->type == 1062 || entry->type == 1021 || entry->type == 1028 || entry->type == 191 || entry->type == 991 || entry->type == 901 || entry->type == 165 || entry->type == 737 || (entry->type == 100 && entry->version == 2) || (entry->type == 430 && entry->version == 2) ? 2u : 1u));
        CHECK(!strcmp(detector->keywords[0], entry->keyword));
        if (entry->type == 7) {
            const br_detector *configured = NULL;
            CHECK(br_generic_new_init(&configured, NULL) == 0 && configured && configured != detector);
            CHECK(!br_detector_is_default(configured, NULL));
            const char *const rest[] = {"token", "cred", "secret", "key"};
            for (size_t j = 0; j < 4; ++j) CHECK(!strcmp(detector->keywords[j + 1], rest[j]));
        }
        if (entry->type == 3 && entry->version == 1) {
            const char *aliases[] = {"az", "entra", "msal", "login.microsoftonline.com", ".onmicrosoft.com"};
            for (size_t j = 0; j < 5; ++j) CHECK(!strcmp(detector->keywords[j + 1], aliases[j]));
        }
        if (entry->type == 196) {
            const char *aliases[] = {"dp.pt.", "dp.st", "dp.sa.", "dp.scim.", "dp.audit."};
            for (size_t j = 0; j < 5; ++j) CHECK(!strcmp(detector->keywords[j + 1], aliases[j]));
        }
        if (entry->type == 987) CHECK(!strcmp(detector->keywords[1], "s-s4t2af-"));
        if (entry->type == 430 && entry->version == 2) CHECK(!strcmp(detector->keywords[1], "bb_ma_"));
        if (entry->type == 39 || entry->type == 1043) CHECK(!strcmp(detector->keywords[1], "ddog-gov"));
        if (entry->type == 920) CHECK(!strcmp(detector->keywords[1], "couchbases://"));
        if (entry->type == 1021) CHECK(!strcmp(detector->keywords[1], "sk-lf-"));
        if (entry->type == 1028) CHECK(!strcmp(detector->keywords[1], "lsv2_sk_"));
        if (entry->type == 191) CHECK(!strcmp(detector->keywords[1], "sdk-"));
        if (entry->type == 165) CHECK(!strcmp(detector->keywords[1], "ladesk"));
        if (entry->type == 991 || entry->type == 992) CHECK(!strcmp(detector->keywords[1], "larksuite"));
        if (entry->type == 992) CHECK(!strcmp(detector->keywords[2], "cli_"));
        if (entry->type == 954) CHECK(!strcmp(detector->keywords[1], "ddw_"));
        if (entry->type == 343) CHECK(!strcmp(detector->keywords[1], "\\\"auths\\"));
        if (entry->type == 18) CHECK(!strcmp(detector->keywords[1], "sl."));
        if (entry->type == 1059) CHECK(!strcmp(detector->keywords[1], "duffel_live_"));
        if (entry->type == 282) CHECK(!strcmp(detector->keywords[1], "easy-insight"));
        if (entry->type == 360) CHECK(!strcmp(detector->keywords[1], "exchange-rate"));
        if (entry->type == 113) {
            br_detector invalid = *detector; invalid.version = 0;
            CHECK(!br_detector_is_default(&invalid, NULL));
            invalid.version = 4; CHECK(!br_detector_is_default(&invalid, NULL));
        }
        if (entry->type == 994) {
            CHECK(!strcmp(detector->keywords[1], "xi-api-key") && !strcmp(detector->keywords[2], "xi_api_key"));
            br_detector versionless = *detector; versionless.version = 0;
            CHECK(!br_detector_is_default(&versionless, NULL));
        }
        if (entry->type == 8) {
            if (entry->version == 1) CHECK(!strcmp(detector->keywords[1], "gh"));
            else {
                const char *const prefixes[] = {"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"};
                for (size_t k = 0; k < 6; ++k) CHECK(!strcmp(detector->keywords[k], prefixes[k]));
            }
        }
        if (entry->type == 107) {
            if (entry->version == 1) {
                CHECK(!strcmp(detector->keywords[1], "hapikey") && !strcmp(detector->keywords[2], "hapi_key") && !strcmp(detector->keywords[3], "hubspot"));
            } else CHECK(!strcmp(detector->keywords[1], "pat-eu1-"));
            br_detector invalid = *detector; invalid.version = 0; CHECK(!br_detector_is_default(&invalid, NULL));
            invalid.version = 3; CHECK(!br_detector_is_default(&invalid, NULL));
        }
        if (entry->type == 120) CHECK(!strcmp(detector->keywords[1], "confluence") && !strcmp(detector->keywords[2], "jira"));
        if (entry->type == 901) CHECK(!strcmp(detector->keywords[1], "ldap://"));
        if (entry->type == 926) CHECK(!strcmp(detector->keywords[1], "api_org_"));
        if (entry->type == 1062) CHECK(!strcmp(detector->keywords[1], "vault"));
        if (entry->type == 876) CHECK(!strcmp(detector->keywords[1], "account-"));
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
        CHECK(detector->max_secret_size == (entry->type == 110 ? 5000 : entry->type == 343 || entry->type == 18 ? 4096 : entry->type == 1013 || entry->type == 6 ? 2048 : entry->type == 983 ? 1024 : entry->type == 829 ? 1300 : -1) &&
              detector->start_offset == (entry->type == 1013 || entry->type == 6 ? 4096 : entry->type == 983 ? 1024 : -1) &&
              detector->max_credential_span == entry->span);
        CHECK(detector->state && detector->scan);
        if (entry->type == 957 || entry->type == 1019 || entry->type == 958 || entry->type == 1024 || entry->type == 975 || entry->type == 10) {
            char *reason = NULL;
            CHECK(detector->false_positive && !detector->false_positive(detector, NULL, &reason));
            CHECK(reason && !strcmp(reason, ""));
            free(reason);
        } else if (entry->type == 6) {
            char *reason = NULL; br_result candidate = {0};
            CHECK(detector->false_positive && !detector->false_positive(detector, NULL, &reason) && !reason);
            CHECK(!detector->false_positive(detector, &candidate, &reason) && !reason);
        } else if (entry->type == 980) {
            br_result candidate = {.raw = {(unsigned char *)"AAAAAAexample", 13}};
            char *reason = NULL;
            CHECK(detector->false_positive && !detector->false_positive(detector, &candidate, &reason));
            CHECK(!reason);
            candidate.raw.data = (unsigned char *)"sample"; candidate.raw.len = 6;
            CHECK(detector->false_positive(detector, &candidate, &reason));
            CHECK(reason && !strcmp(reason, "matches term: sample"));
            free(reason);
        } else if (entry->type == 899) {
            static const unsigned char allowed[] = "ftp://example:sample@fixture.invalid";
            static const unsigned char filtered[] = "ftp://user:pass@FTP.FreeBSD.ORG";
            br_result candidate = {.detector_type = 899, .raw = {(unsigned char *)allowed, sizeof(allowed) - 1}};
            char *reason = NULL;
            CHECK(detector->false_positive && !detector->false_positive(detector, &candidate, &reason) && !reason);
            candidate.raw.data = (unsigned char *)filtered; candidate.raw.len = sizeof(filtered) - 1;
            CHECK(detector->false_positive(detector, &candidate, &reason));
            CHECK(reason && !strcmp(reason, "contains term: @ftp.freebsd.org"));
            free(reason);
        } else if (entry->type == 991) {
            static const unsigned char extension[] = "t-1234567890abcd.JSON";
            br_result candidate = {.detector_type = 991, .raw = {(unsigned char *)extension, sizeof(extension) - 1}};
            char *reason = NULL;
            CHECK(detector->false_positive && detector->false_positive(detector, &candidate, &reason));
            CHECK(reason && !*reason);
            free(reason);
        } else if (entry->type == 114 && entry->version == 2) {
            br_result candidate = {0};
            char *reason = NULL;
            CHECK(detector->false_positive && !detector->false_positive(detector, &candidate, &reason) && !reason);
        } else CHECK(!detector->false_positive);
        if (entry->type == 2 || entry->type == 959) CHECK(detector->clean && detector->clean_always);
        else CHECK(!detector->clean && !detector->clean_always);
        if (entry->type == 181 || entry->type == 1042 || entry->type == 1047 || entry->type == 1061 || entry->type == 1062) {
            CHECK(detector->validate_endpoints && detector->cloud_endpoint);
            CHECK(!detector->cloud_endpoint[0]);
        } else if (entry->type == 39 || entry->type == 1043) {
            CHECK(detector->validate_endpoints && detector->cloud_endpoint);
            CHECK(!strcmp(detector->cloud_endpoint, "https://api.datadoghq.com"));
        } else if (entry->type == 120) {
            CHECK(detector->validate_endpoints && detector->cloud_endpoint && !strcmp(detector->cloud_endpoint, "https://api.atlassian.com"));
        } else if (entry->type == 9 || entry->type == 1050) {
            CHECK(detector->validate_endpoints && detector->cloud_endpoint && !strcmp(detector->cloud_endpoint, "https://gitlab.com"));
        } else if (entry->type == 8) {
            CHECK(detector->validate_endpoints && detector->cloud_endpoint && !strcmp(detector->cloud_endpoint, "https://api.github.com"));
        } else if (entry->type == 1045 || entry->type == 1046 || entry->type == 1036) {
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
