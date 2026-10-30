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
    br_cexio_init,
    br_chartmogul_init,
    br_chatbot_init,
    br_chatfule_init,
    br_checio_init,
    br_checklyhq_init,
    br_checkout_init,
    br_checkvist_init,
    br_cicero_init,
    br_circleci_v1_init,
    br_circleci_v2_init,
    br_clarifai_init,
    br_clearbit_init,
    br_clickhelp_init,
    br_clicksendsms_init,
    br_clickuppersonaltoken_init,
    br_cliengo_init,
    br_clientary_init,
    br_clinchpad_init,
    br_clockify_init,
    br_clockworksms_init,
    br_closecrm_init,
    br_cloudconvert_init,
    br_cloudelements_init,
    br_cloudflareapitoken_v1_init,
    br_cloudflareapitoken_v2_init,
    br_cloudflarecakey_init,
    br_cloudflareglobalapikey_v1_init,
    br_cloudflareglobalapikey_v2_init,
    br_cloudimage_init,
    br_cloudinary_init,
    br_cloudmersive_init,
    br_cloudplan_init,
    br_cloudsmith_init,
    br_cloverly_init,
    br_cloze_init,
    br_clustdoc_init,
    br_coda_init,
    br_codacy_init,
    br_codeclimate_init,
    br_codemagic_init,
    br_codequiry_init,
    br_coinapi_init,
    br_coinbase_init,
    br_coinlayer_init,
    br_coinlib_init,
    br_collect2_init,
    br_column_init,
    br_commercejs_init,
    br_commodities_init,
    br_companyhub_init,
    br_confluencedatacenter_init,
    br_confluent_init,
    br_contentfulpersonalaccesstoken_init,
    br_conversiontools_init,
    br_convertapi_init,
    br_convertkit_init,
    br_convier_init,
    br_copper_init,
    br_couchbase_init,
    br_countrylayer_init,
    br_courier_init,
    br_coveralls_init,
    br_craftmypdf_init,
    br_crowdin_init,
    br_cryptocompare_init,
    br_currencycloud_init,
    br_currencyfreaks_init,
    br_currencylayer_init,
    br_currencyscoop_init,
    br_currentsapi_init,
    br_customerguru_init,
    br_customerio_init,
    br_d7network_init,
    br_dailyco_init,
    br_dandelion_init,
    br_dareboost_init,
    br_databox_init,
    br_databrickstoken_init,
    br_datadogapikey_init,
    br_datadogtoken_init,
    br_datagov_init,
    br_debounce_init,
    br_deepai_init,
    br_deepgram_init,
    br_deepseek_init,
    br_delighted_init,
    br_demio_init,
    br_denodeploy_init,
    br_deputy_init,
    br_detectify_init,
    br_detectlanguage_init,
    br_dfuse_init,
    br_diffbot_init,
    br_diggernaut_init,
    br_digitaloceantoken_init,
    br_digitaloceanv2_init,
    br_discordbottoken_init,
    br_discordwebhook_init,
    br_disqus_init,
    br_ditto_init,
    br_dnscheck_init,
    br_docker_init,
    br_dockerhub_v1_init,
    br_dockerhub_v2_init,
    br_docparser_init,
    br_documo_init,
    br_docusign_init,
    br_doppler_init,
    br_dotdigital_init,
    br_dovico_init,
    br_dronahq_init,
    br_droneci_init,
    br_dropbox_init,
    br_duffeltoken_init,
    br_duo_init,
    br_duply_init,
    br_dwolla_init,
    br_dynalist_init,
    br_dyspatch_init,
    br_eagleeyenetworks_init,
    br_easyinsight_init,
    br_ecostruxureit_init,
    br_edamam_init,
    br_edenai_init,
    br_eightxeight_init,
    br_elasticemail_init,
    br_elevenlabs_v1_init,
    br_elevenlabs_v2_init,
    br_enablex_init,
    br_endorlabs_init,
    br_enigma_init,
    br_envoyapikey_init,
    br_eraser_init,
    br_etherscan_init,
    br_ethplorer_init,
    br_eventbrite_init,
    br_everhour_init,
    br_exchangerateapi_init,
    br_exchangeratesapi_init,
    br_exportsdk_init,
    br_extractorapi_init,
    br_facebookoauth_init,
    br_faceplusplus_init,
    br_fastforex_init,
    br_fastlypersonaltoken_init,
    br_feedier_init,
    br_fetchrss_init,
    br_fibery_init,
    br_figmapersonalaccesstoken_v1_init,
    br_figmapersonalaccesstoken_v2_init,
    br_figmapersonalaccesstoken_v3_init,
    br_fileio_init,
    br_finage_init,
    br_financialmodelingprep_init,
    br_findl_init,
    br_finnhub_init,
    br_fixerio_init,
    br_flatio_init,
    br_fleetbase_init,
    br_flexport_init,
    br_flickr_init,
    br_flightapi_init,
    br_flightlabs_init,
    br_flightstats_init,
    br_float_init,
    br_flowflu_init,
    br_flutterwave_init,
    br_flyio_init,
    br_fmfw_init,
    br_formbucket_init,
    br_formcraft_init,
    br_formio_init,
    br_formsite_init,
    br_foursquare_init,
    br_frameio_init,
    br_freshbooks_init,
    br_freshdesk_init,
    br_front_init,
    br_ftp_init,
    br_fulcrum_init,
    br_fullstory_v1_init,
    br_fullstory_v2_init,
    br_fxmarket_init,
    br_gcp_init,
    br_gcpapplicationdefaultcredentials_init,
    br_geckoboard_init,
    br_gemini_init,
    br_generic_init,
    br_gengo_init,
    br_geoapify_init,
    br_geocode_init,
    br_geocodify_init,
    br_geocodio_init,
    br_geoipifi_init,
    br_getemail_init,
    br_getemails_init,
    br_getgeoapi_init,
    br_getgist_init,
    br_getresponse_init,
    br_getsandbox_init,
    br_github_v1_init,
    br_github_v2_init,
    br_github_oauth2_init,
    br_githubapp_init,
    br_gitlab_v1_init,
    br_gitlab_v2_init,
    br_gitlab_v3_init,
    br_gitlaboauth2_init,
    br_gitter_init,
    br_glassnode_init,
    br_gocanvas_init,
    br_gocardless_init,
    br_godaddy_v1_init,
    br_godaddy_v2_init,
    br_goodday_init,
    br_googlegemini_init,
    br_googleoauth2_init,
    br_grafana_init,
    br_grafanaserviceaccount_init,
    br_graphcms_init,
    br_graphhopper_init,
    br_groovehq_init,
    br_groq_init,
    br_gtmetrix_init,
    br_guardianapi_init,
    br_gumroad_init,
    br_guru_init,
    br_gyazo_init,
    br_happyscribe_init,
    br_harness_init,
    br_harvest_init,
    br_hashicorpvaultbatchtoken_init,
    br_hashicorpvaultauth_init,
    br_hashicorpvaulttoken_init,
    br_hasura_init,
    br_hellosign_init,
    br_helpcrunch_init,
    br_helpscout_init,
    br_hereapi_init,
    br_heroku_v1_init,
    br_heroku_v2_init,
    br_hive_init,
    br_hiveage_init,
    br_holidayapi_init,
    br_holistic_init,
    br_honeycomb_init,
    br_host_init,
    br_html2pdf_init,
    br_hubspot_apikey_v1_init,
    br_hubspot_apikey_v2_init,
    br_huggingface_init,
    br_humanity_init,
    br_hunter_init,
    br_hybiscus_init,
    br_hypertrack_init,
    br_ibmclouduserkey_init,
    br_iconfinder_init,
    br_iexapis_init,
    br_iexcloud_init,
    br_imagekit_init,
    br_imagga_init,
    br_impala_init,
    br_infura_init,
    br_insightly_init,
    br_instabot_init,
    br_instamojo_init,
    br_intercom_init,
    br_interseller_init,
    br_intra42_init,
    br_intrinio_init,
    br_invoiceocean_init,
    br_ip2location_init,
    br_ipapi_init,
    br_ipgeolocation_init,
    br_ipinfo_init,
    br_ipinfodb_init,
    br_ipquality_init,
    br_ipstack_init,
    br_jiradatacenterpat_init,
    br_jotform_init,
    br_jumpcloud_init,
    br_juro_init,
    br_kanban_init,
    br_leadfeeder_init,
    br_locationiq_init,
    br_loginradius_init,
    br_madkudu_init,
    br_mailerlite_init,
    br_jupiterone_init,
    br_magicbell_init,
    br_mailboxlayer_init,
    br_mailjetbasicauth_init,
    br_mailjetsms_init,
    br_kanbantool_init,
    br_karmacrm_init,
    br_keenio_init,
    br_kickbox_init,
    br_klipfolio_init,
    br_knapsackpro_init,
    br_klaviyo_init,
    br_kontent_init,
    br_meistertask_init,
    br_messagebird_init,
    br_kraken_init,
    br_kucoin_init,
    br_kylas_init,
    br_langfuse_init,
    br_langsmith_init,
    br_languagelayer_init,
    br_larksuite_init,
    br_larksuiteapikey_init,
    br_launchdarkly_init,
    br_lemlist_init,
    br_lemonsqueezy_init,
    br_ldap_init,
    br_lendflow_init,
    br_lessannoyingcrm_init,
    br_lexigram_init,
    br_linearapi_init,
    br_jiratoken_v1_init,
    br_jiratoken_v2_init,
    br_loadmill_init,
    br_meraki_init,
    br_linemessaging_init,
    br_linenotify_init,
    br_linkpreview_init,
    br_livestorm_init,
    br_liveagent_init,
    br_jdbc_init,
    br_miro_init,
    br_mixmax_init,
    br_mixpanel_init,
    br_mite_init,
    br_moderation_init,
    br_mindmeister_init,
    br_monkeylearn_init,
    br_mockaroo_init,
    br_monday_init,
    br_mailmodo_init,
    br_netsuite_init,
    br_neutrinoapi_init,
    br_newsapi_init,
    br_ngc_init,
    br_newscatcher_init,
    br_ngrok_init,
    br_nexmoapikey_init,
    br_moonclerk_init,
    br_moralis_init,
    br_moosend_init,
    br_myintervals_init,
    br_nasdaqdatalink_init,
    br_mux_init,
    br_myfreshworks_init,
    br_nethunt_init,
    br_mrticktock_init,
    br_netlify_v1_init,
    br_netlify_v2_init,
    br_mediastack_init,
    br_metabase_init,
    br_metrilo_init,
    br_metaapi_init,
    br_mesibo_init,
    br_microsoftteamswebhook_v1_init,
    br_microsoftteamswebhook_v2_init,
    br_lob_init,
    br_lokalisetoken_init,
    br_loggly_init,
    br_logzio_init,
    br_newrelicbrowserkey_init,
    br_newrelicinsightsinsertkey_init,
    br_newrelicinsightsquerykey_init,
    br_newreliclicensekey_init,
    br_newrelicmobileapptoken_init,
    br_newrelicpersonalapikey_init,
    br_newrelicuserkey_init,
    br_luno_init,
    br_loyverse_init,
    br_lunchmoney_init,
    br_onesignal_init,
    br_onfleet_init,
    br_onepagecrm_init,
    br_nftport_init,
    br_nightfall_init,
    br_mailsac_init,
    br_mapquest_init,
    br_mavenlink_init,
    br_mapbox_init,
    br_maxmindlicense_v1_init,
    br_maxmindlicense_v2_init,
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
        case 100: {
            if (detector->version == 1) return true;
            if (detector->version != 2) return false;
            /* OSS main enables v2; explicit false retains package-zero state.
             * This exact boolean never changes legacy v1 or other detectors. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "CloudflareApiTokenV2DetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 58: {
            if (detector->version == 1) return true;
            if (detector->version != 2) return false;
            /* The global-key flag never disables legacy v1. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "CloudflareGlobalApiKeyV2DetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 405: {
            if (detector->version != 0) return false;
            /* OSS main enables Enigma; explicit false retains package zero. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "EnigmaDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1048: {
            if (detector->version != 0) return false;
            /* OSS main enables Cloudinary; explicit false retains package zero. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "CloudinaryDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1043: {
            if (detector->version != 0) return false;
            /* OSS main enables this exact flag; package-zero remains false. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "DatadogApiKeyDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1063: {
            if (detector->version != 0) return false;
            /* OSS main enables Duo; package atomic-zero remains false. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "DuoDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1059: {
            if (detector->version != 0) return false;
            /* OSS main enables DuffelToken; package atomic-zero remains false. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "DuffelTokenDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1050: {
            if (detector->version != 0) return false;
            /* OSS main enables GitLab OAuth; explicit false models package zero. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "GitLabOAuthDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
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
        case 1061: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "HashiCorpVaultBatchTokenDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1062: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "HashiCorpVaultTokenDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 939: {
            if (detector->version != 0) return false;
            /* OSS main enables IPInfo; explicit false models package zero. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "IPInfoDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 9: case 113: return detector->version >= 1 && detector->version <= 3;
        case 3: case 4: case 8: case 19: case 107: case 142: case 190: case 303: case 333: case 394: case 430: case 708: case 921: case 994: case 1008: case 120: case 74: case 114: case 96: return detector->version == 1 || detector->version == 2;
        case 0: case 5: case 6: case 983: case 696: case 876: case 529: case 486: case 542: case 18: case 36: case 39: case 40: case 138: case 192: case 196: case 149: case 150: case 158: case 237: case 238: case 239: case 249: case 254: case 255: case 256: case 258: case 259: case 265: case 521: case 390: case 431: case 432: case 433: case 434: case 436: case 678: case 681: case 683: case 684: case 685: case 692: case 334: case 335: case 343: case 693: case 197: case 199: case 802: case 805: case 808:
        case 125: case 126: case 130: case 135: case 277: case 1014: case 1015: case 498: case 499: case 501: case 506: case 507: case 910: case 917: case 919: case 920: case 923: case 924: case 905: case 907:
        case 302: case 565: case 566: case 567: case 568: case 569: case 707: case 709: case 710: case 711: case 712: case 713: case 714: case 721: case 723: case 726: case 727: case 756: case 762: case 763: case 828: case 829: case 830: case 831: case 833: case 834: case 838: case 839: case 861: case 863: case 844: case 845: case 848: case 354: case 358: case 359: case 360: case 366: case 375: case 379: case 380: case 381: case 382: case 383: case 522: case 523: case 524: case 525: case 526: case 527: case 528: case 170: case 173: case 163: case 399: case 467: case 473: case 474: case 477: case 453:
        case 448: case 454: case 455: case 456: case 457: case 42: case 43: case 44: case 933: case 179: case 1032: case 632: case 633: case 209: case 210: case 211: case 212: case 214: case 215: case 223: case 225: case 226: case 458:
        case 1002: case 1003: case 401: case 402: case 403: case 404: case 406: case 407: case 416: case 418: case 420: case 423: case 424: case 426: case 427: case 428: case 391: case 393: case 484: case 485: case 783: case 784: case 788: case 789: case 792: case 636: case 637: case 639: case 642: case 647: case 648: case 649: case 650: case 651: case 652: case 653: case 654: case 664: case 665: case 666: case 667: case 643: case 206: case 208: case 1004: case 768: case 769: case 770: case 771: case 588: case 592: case 598:
        case 307: case 311: case 317: case 318: case 320: case 322: case 812: case 815: case 816: case 819: case 821: case 823: case 646: case 269: case 270: case 278: case 280: case 281: case 282: case 283: case 284: case 285: case 286: case 1041: case 1042: case 180: case 181: case 184: case 185: case 187: case 189: case 385: case 386: case 387: case 388: case 389: case 794: case 800: case 801: case 897: case 899:
        case 98: case 103: case 41: case 376: case 377: case 378: case 166: case 1045: case 1047: case 1046: case 1026:
        case 578: case 602: case 603: case 604: case 619: case 621: case 110: case 112: case 55: case 56: case 57: case 59: case 60: case 62: case 64: case 65: case 66: case 68: case 69: case 323: case 324: case 325: case 554: case 555: case 564: case 511: case 512: case 513: case 733: case 739: case 749: case 2: case 1052: case 959: case 960: case 962: case 963: case 980: case 988: case 990: case 993: case 947: case 953: case 954: case 957: case 971: case 1013: case 1007: case 1009: case 931: case 1018: case 1019: case 1025: case 1029: case 958: case 972: case 976: case 977: case 1024: case 975: case 1020: case 260: case 1036: case 1030: case 395: case 164: case 153: case 408: case 572: case 361: case 764: case 877: case 556: case 355: case 926: case 508: case 72: case 773: case 459: case 487: case 813: case 557: case 250: case 349: case 509: case 906: case 271: case 856: case 941: case 156: case 858: case 987: case 579: case 689: case 940: case 362: case 356: case 530:
        case 478: case 133: case 287: case 131: case 295: case 686: case 329: case 450: case 510: case 715: case 228:
        case 982: case 786: case 145: case 105: case 106:
        case 853: case 296: case 140: case 573: case 740: case 760: case 935: case 328: case 656: case 111: case 186: case 736: case 272: case 1021: case 1028: case 489: case 991: case 992: case 191: case 841: case 952: case 901: case 668: case 267: case 437: case 177: case 758: case 1000: case 176: case 438: case 735: case 165: case 10: case 774: case 700: case 682: case 669: case 657: case 820: case 753: case 246: case 157: case 995: case 623: case 207: case 896: case 543: case 966: case 121: case 698: case 909: case 261: case 688: case 748: case 216: case 268: case 691: case 531: case 950: case 297: case 737: case 503: case 490: case 129: case 944: case 961: case 50: case 1058: case 1064: case 1065: case 1066: case 1067: case 1068: case 655: case 396: case 797: case 835: case 986: case 273: case 213: case 847: case 481: case 336: case 468: case 104:
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
    case 4: return "Circle";
    case 5: return "Coinbase";
    case 6: return "GCP";
    case 7: return "Generic";
    case 8: return "Github";
    case 9: return "Gitlab";
    case 18: return "Dropbox";
    case 19: return "Heroku";
    case 36: return "GitHubApp";
    case 39: return "DatadogToken";
    case 40: return "FacebookOAuth";
    case 41: return "AsanaPersonalAccessToken";
    case 42: return "AmplitudeApiKey";
    case 43: return "BitLyAccessToken";
    case 44: return "CalendlyApiKey";
    case 55: return "Auth0oauth";
    case 56: return "Bitfinex";
    case 57: return "Clarifai";
    case 58: return "CloudflareGlobalApiKey";
    case 59: return "CloudflareCaKey";
    case 60: return "Confluent";
    case 62: return "DatabricksToken";
    case 64: return "DigitalOceanToken";
    case 65: return "DiscordBotToken";
    case 66: return "DiscordWebhook";
    case 68: return "FastlyPersonalToken";
    case 69: return "GoogleOauth2";
    case 72: return "Hunter";
    case 73: return "IbmCloudUserKey";
    case 98: return "AsanaOauth";
    case 100: return "CloudflareApiToken";
    case 103: return "ContentfulPersonalAccessToken";
    case 107: return "HubSpotApiKey";
    case 110: return "Auth0ManagementApiToken";
    case 112: return "ElasticEmail";
    case 113: return "FigmaPersonalAccessToken";
    case 125: return "AirbrakeProjectKey";
    case 126: return "AirbrakeUserKey";
    case 130: return "Calendarific";
    case 135: return "DroneCI";
    case 136: return "AdobeIO";
    case 138: return "D7Network";
    case 142: return "Buildkite";
    case 149: return "FixerIO";
    case 150: return "ButterCMS";
    case 153: return "Helpscout";
    case 156: return "Intercom";
    case 158: return "CannyIo";
    case 163: return "Ayrshare";
    case 164: return "HelpCrunch";
    case 166: return "Beamer";
    case 170: return "AlgoliaAdminKey";
    case 173: return "Flutterwave";
    case 179: return "Anypoint";
    case 180: return "Dwolla";
    case 181: return "ArtifactoryAccessToken";
    case 184: return "GoCardless";
    case 185: return "Codacy";
    case 187: return "Checkout";
    case 189: return "ClockworkSMS";
    case 190: return "Atlassian";
    case 192: return "Coveralls";
    case 196: return "Doppler";
    case 197: return "Agora";
    case 199: return "FrameIO";
    case 206: return "Groovehq";
    case 208: return "Chatbot";
    case 209: return "ClickSendsms";
    case 210: return "Getgist";
    case 211: return "CustomerIO";
    case 212: return "ApiDeck";
    case 214: return "Copper";
    case 215: return "Close";
    case 223: return "GraphCMS";
    case 225: return "Convertkit";
    case 226: return "CustomerGuru";
    case 237: return "Delighted";
    case 238: return "Feedier";
    case 239: return "Abyssale";
    case 249: return "Float";
    case 250: return "Imagekit";
    case 254: return "Campayn";
    case 255: return "Clinchpad";
    case 256: return "CompanyHub";
    case 258: return "Dyspatch";
    case 259: return "Guardianapi";
    case 260: return "Harvest";
    case 265: return "FlowFlu";
    case 257: return "Debounce";
    case 269: return "Apptivo";
    case 270: return "CapsuleCRM";
    case 271: return "Insightly";
    case 277: return "Airship";
    case 278: return "Artsy";
    case 280: return "Clockify";
    case 281: return "Dnscheck";
    case 282: return "EasyInsight";
    case 283: return "Ethplorer";
    case 284: return "Everhour";
    case 285: return "Fulcrum";
    case 286: return "GeoIpifi";
    case 293: return "Apollo";
    case 301: return "Alconost";
    case 302: return "Blogger";
    case 303: return "Accuweather";
    case 307: return "Clientary";
    case 311: return "Documo";
    case 317: return "Bulbul";
    case 318: return "CentralStationCRM";
    case 320: return "Axonaut";
    case 322: return "Appcues";
    case 323: return "Autoklose";
    case 324: return "Cloudplan";
    case 325: return "Dotdigital";
    case 326: return "GetEmail";
    case 327: return "GetEmails";
    case 333: return "Brandfetch";
    case 334: return "Clearbit";
    case 335: return "Crowdin";
    case 343: return "Docker";
    case 349: return "Imagga";
    case 354: return "Currencylayer";
    case 355: return "Html2Pdf";
    case 356: return "IPGeolocation";
    case 358: return "Cloudmersive";
    case 359: return "Dynalist";
    case 360: return "ExchangeRateAPI";
    case 361: return "HolidayAPI";
    case 362: return "Ipapi";
    case 366: return "ClickupPersonalToken";
    case 375: return "Alegra";
    case 376: return "Audd";
    case 377: return "Baremetrics";
    case 378: return "Coinlib";
    case 379: return "ExchangeRatesAPI";
    case 380: return "CurrencyScoop";
    case 381: return "FXMarket";
    case 382: return "CurrencyCloud";
    case 383: return "GetGeoAPI";
    case 384: return "Abstract";
    case 385: return "Billomat";
    case 386: return "Dovico";
    case 387: return "Bitbar";
    case 388: return "Bugsnag";
    case 389: return "AssemblyAI";
    case 390: return "AdafruitIO";
    case 391: return "Apify";
    case 393: return "CryptoCompare";
    case 394: return "Fullstory";
    case 395: return "HelloSign";
    case 399: return "AlienVault";
    case 401: return "Apiflash";
    case 402: return "Coinlayer";
    case 403: return "CurrentsAPI";
    case 404: return "DataGov";
    case 405: return "Enigma";
    case 406: return "FinancialModelingPrep";
    case 407: return "Geocodio";
    case 408: return "HereAPI";
    case 416: return "FacePlusPlus";
    case 418: return "Deepgram";
    case 420: return "Finnhub";
    case 423: return "Finage";
    case 424: return "Edamam";
    case 426: return "Gengo";
    case 427: return "Front";
    case 428: return "Fleetbase";
    case 430: return "Bannerbear";
    case 431: return "Adzuna";
    case 432: return "BitcoinAverage";
    case 433: return "CommerceJS";
    case 434: return "DetectLanguage";
    case 436: return "Graphhopper";
    case 448: return "Browshot";
    case 453: return "Amadeus";
    case 454: return "FourSquare";
    case 455: return "Flickr";
    case 456: return "ClickHelp";
    case 457: return "Ambee";
    case 458: return "Api2Cart";
    case 459: return "Hypertrack";
    case 467: return "Gyazo";
    case 473: return "Allsports";
    case 474: return "CalorieNinja";
    case 477: return "Cicero";
    case 484: return "ApiFonica";
    case 485: return "Aylien";
    case 486: return "Geocode";
    case 487: return "IconFinder";
    case 498: return "AirVisual";
    case 499: return "Currencyfreaks";
    case 501: return "FlatIO";
    case 506: return "Besttime";
    case 507: return "Happyscribe";
    case 508: return "Humanity";
    case 509: return "Impala";
    case 511: return "AutoPilot";
    case 512: return "Bitmex";
    case 513: return "ClustDoc";
    case 521: return "AbuseIPDB";
    case 522: return "AletheiaApi";
    case 523: return "BlitApp";
    case 524: return "Censys";
    case 525: return "Cloverly";
    case 526: return "CountryLayer";
    case 527: return "FileIO";
    case 528: return "FlightApi";
    case 529: return "Geoapify";
    case 530: return "IPinfoDB";
    case 542: return "Geocodify";
    case 554: return "CoinApi";
    case 555: return "Gitter";
    case 556: return "Host";
    case 557: return "Iexcloud";
    case 564: return "AviationStack";
    case 565: return "BombBomb";
    case 566: return "Commodities";
    case 567: return "Dfuse";
    case 568: return "EdenAI";
    case 569: return "Glassnode";
    case 570: return "Guru";
    case 571: return "Hive";
    case 572: return "Hiveage";
    case 578: return "CarbonInterface";
    case 579: return "Intrinio";
    case 585: return "DailyCO";
    case 588: return "Appfollow";
    case 592: return "Fetchrss";
    case 598: return "BuddyNS";
    case 602: return "Bugherd";
    case 603: return "Blazemeter";
    case 604: return "Autodesk";
    case 619: return "Dandelion";
    case 621: return "DeepAI";
    case 632: return "Apacta";
    case 633: return "GetSandbox";
    case 636: return "FastForex";
    case 637: return "APIMatic";
    case 639: return "EagleEyeNetworks";
    case 642: return "Flightstats";
    case 643: return "ChecIO";
    case 646: return "AppSynergy";
    case 647: return "Caflou";
    case 648: return "Caspio";
    case 649: return "ChecklyHQ";
    case 650: return "CloudElements";
    case 651: return "DronaHQ";
    case 652: return "Enablex";
    case 653: return "Fmfw";
    case 654: return "GoodDay";
    case 664: return "Convier";
    case 665: return "Courier";
    case 666: return "Ditto";
    case 667: return "Findl";
    case 678: return "Freshdesk";
    case 681: return "Freshbooks";
    case 683: return "Deputy";
    case 684: return "Beebole";
    case 685: return "Cashboard";
    case 689: return "InvoiceOcean";
    case 692: return "Chatfule";
    case 693: return "Aeroworkflow";
    case 696: return "Geckoboard";
    case 707: return "BoostNote";
    case 708: return "CaptainData";
    case 709: return "Checkvist";
    case 710: return "Cliengo";
    case 711: return "Cloze";
    case 712: return "FormIO";
    case 713: return "FormBucket";
    case 714: return "GoCanvas";
    case 721: return "CloudImage";
    case 723: return "Borgbase";
    case 726: return "Diffbot";
    case 727: return "EightxEight";
    case 733: return "AvazaPersonalAccessToken";
    case 739: return "CexIO";
    case 749: return "Column";
    case 756: return "BrowserStack";
    case 762: return "Dareboost";
    case 763: return "GTMetrix";
    case 764: return "Holistic";
    case 768: return "APITemplate";
    case 769: return "ConversionTools";
    case 770: return "CraftMyPDF";
    case 771: return "ExportSDK";
    case 773: return "Hybiscus";
    case 783: return "Codequiry";
    case 784: return "ExtractorAPI";
    case 788: return "Apilayer";
    case 789: return "Disqus";
    case 792: return "Gumroad";
    case 794: return "Detectify";
    case 800: return "Atera";
    case 801: return "EcoStruxureIT";
    case 802: return "Aha";
    case 805: return "Cloudsmith";
    case 808: return "Fibery";
    case 812: return "Formcraft";
    case 813: return "Iexapis";
    case 815: return "Chartmogul";
    case 816: return "Appointedd";
    case 819: return "Diggernaut";
    case 821: return "Duply";
    case 823: return "Collect2";
    case 828: return "BraintreePayments";
    case 829: return "CloudConvert";
    case 830: return "Grafana";
    case 831: return "ConvertApi";
    case 833: return "Bulksms";
    case 834: return "Databox";
    case 838: return "Docparser";
    case 839: return "Formsite";
    case 844: return "Codeclimate";
    case 845: return "Codemagic";
    case 848: return "FlightLabs";
    case 856: return "Instabot";
    case 858: return "Interseller";
    case 861: return "Getresponse";
    case 863: return "Demio";
    case 867: return "Besnappy";
    case 876: return "Gemini";
    case 877: return "Honeycomb";
    case 897: return "DigitalOceanV2";
    case 899: return "FTP";
    case 905: return "Etherscan";
    case 906: return "Infura";
    case 907: return "Alchemy";
    case 908: return "BlockNative";
    case 910: return "BscScan";
    case 917: return "Aiven";
    case 919: return "Docusign";
    case 920: return "Couchbase";
    case 921: return "Dockerhub";
    case 923: return "EnvoyApiKey";
    case 924: return "GitHubOauth2";
    case 926: return "HuggingFace";
    case 931: return "AzureStorage";
    case 933: return "Anthropic";
    case 939: return "IPInfo";
    case 940: return "Ip2location";
    case 941: return "Instamojo";
    case 947: return "BetterStack";
    case 953: return "Budibase";
    case 954: return "DenoDeploy";
    case 957: return "AzureBatch";
    case 958: return "AzureContainerRegistry";
    case 959: return "AWSSessionKey";
    case 960: return "Coda";
    case 962: return "Eventbrite";
    case 963: return "GrafanaServiceAccount";
    case 971: return "AzureCosmosDBKeyIdentifiable";
    case 972: return "AzureDevopsPersonalAccessToken";
    case 973: return "AzureFunctionKey";
    case 975: return "AzureSasToken";
    case 976: return "AzureSearchAdminKey";
    case 977: return "AzureSearchQueryKey";
    case 980: return "FlyIO";
    case 983: return "GCPApplicationDefaultCredentials";
    case 987: return "Intra42";
    case 988: return "Groq";
    case 990: return "Eraser";
    case 993: return "EndorLabs";
    case 994: return "ElevenLabs";
    case 1002: return "Box";
    case 1003: return "BoxOauth";
    case 1004: return "ApiMetrics";
    case 1007: return "AzureOpenAI";
    case 1008: return "GoDaddy";
    case 1009: return "Flexport";
    case 1013: return "AzureRefreshToken";
    case 1014: return "AirtableOAuth";
    case 1015: return "AirtablePersonalAccessToken";
    case 1018: return "AzureApiManagementRepositoryKey";
    case 1019: return "AzureAPIManagementSubscriptionKey";
    case 1020: return "Harness";
    case 1024: return "AzureDirectManagementKey";
    case 1025: return "AzureAppConfigConnectionString";
    case 1026: return "DeepSeek";
    case 1029: return "BitbucketAppPassword";
    case 1030: return "Hasura";
    case 1032: return "AnypointOAuth2";
    case 1036: return "HashiCorpVaultAuth";
    case 1041: return "GoogleGeminiAPIKey";
    case 1042: return "ArtifactoryReferenceToken";
    case 1043: return "DatadogApikey";
    case 1045: return "BitbucketDataCenter";
    case 1046: return "JiraDataCenterPAT";
    case 1047: return "ConfluenceDataCenter";
    case 1048: return "Cloudinary";
    case 1050: return "GitLabOauth2";
    case 1052: return "AWSAppSync";
    case 1053: return "BrainTrustApiKey";
    case 1059: return "DuffelToken";
    case 1061: return "HashiCorpVaultBatchToken";
    case 1062: return "HashiCorpVaultToken";
    case 1063: return "Duo";
    case 478: return "IPQuality";
    case 133: return "IpStack";
    case 287: return "Jotform";
    case 131: return "Jumpcloud";
    case 295: return "Juro";
    case 686: return "Kanban";
    case 982: return "JupiterOne";
    case 786: return "MagicBell";
    case 145: return "Mailboxlayer";
    case 105: return "MailJetBasicAuth";
    case 106: return "MailJetSMS";
    case 853: return "Kanbantool";
    case 296: return "KarmaCRM";
    case 140: return "KeenIO";
    case 573: return "Kickbox";
    case 740: return "Klipfolio";
    case 760: return "KnapsackPro";
    case 935: return "Klaviyo";
    case 328: return "Kontent";
    case 656: return "Meistertask";
    case 111: return "MessageBird";
    case 186: return "Kraken";
    case 736: return "KuCoin";
    case 272: return "Kylas";
    case 1021: return "Langfuse";
    case 1028: return "LangSmith";
    case 489: return "LanguageLayer";
    case 991: return "LarkSuite";
    case 992: return "LarkSuiteApiKey";
    case 191: return "LaunchDarkly";
    case 841: return "Lemlist";
    case 952: return "LemonSqueezy";
    case 901: return "LDAP";
    case 668: return "Lendflow";
    case 267: return "LessAnnoyingCRM";
    case 437: return "Lexigram";
    case 177: return "LinearAPI";
    case 120: return "JiraToken";
    case 758: return "Loadmill";
    case 1000: return "Meraki";
    case 168: return "LineMessaging";
    case 176: return "LineNotify";
    case 438: return "LinkPreview";
    case 735: return "Livestorm";
    case 165: return "LiveAgent";
    case 10: return "JDBC";
    case 774: return "Miro";
    case 700: return "Mixmax";
    case 371: return "Mixpanel";
    case 682: return "Mite";
    case 669: return "Moderation";
    case 657: return "Mindmeister";
    case 820: return "MonkeyLearn";
    case 753: return "Mockaroo";
    case 246: return "Monday";
    case 157: return "Mailmodo";
    case 995: return "Netsuite";
    case 623: return "NeutrinoApi";
    case 207: return "Newsapi";
    case 896: return "NGC";
    case 543: return "Newscatcher";
    case 966: return "Ngrok";
    case 121: return "NexmoApiKey";
    case 698: return "Moonclerk";
    case 909: return "Moralis";
    case 261: return "Moosend";
    case 688: return "MyIntervals";
    case 532: return "NasdaqDataLink";
    case 748: return "Mux";
    case 216: return "Myfreshworks";
    case 268: return "Nethunt";
    case 691: return "Mrticktock";
    case 74: return "Netlify";
    case 531: return "MediaStack";
    case 950: return "Metabase";
    case 297: return "Metrilo";
    case 737: return "MetaAPI";
    case 503: return "Mesibo";
    case 114: return "MicrosoftTeamsWebhook";
    case 490: return "Lob";
    case 129: return "LokaliseToken";
    case 944: return "Loggly";
    case 961: return "LogzIO";
    case 50: return "NewRelicPersonalApiKey";
    case 1058: return "NewRelicInsightsInsertKey";
    case 1064: return "NewRelicLicenseKey";
    case 1065: return "NewRelicBrowserKey";
    case 1066: return "NewRelicUserKey";
    case 1067: return "NewRelicInsightsQueryKey";
    case 1068: return "NewRelicMobileAppToken";
    case 655: return "Luno";
    case 396: return "Loyverse";
    case 797: return "LunchMoney";
    case 835: return "Onesignal";
    case 986: return "Onfleet";
    case 273: return "OnepageCRM";
    case 213: return "Nftport";
    case 847: return "Nightfall";
    case 481: return "Mailsac";
    case 336: return "Mapquest";
    case 468: return "Mavenlink";
    case 104: return "MapBox";
    case 96: return "MaxMindLicense";
    case 329: return "Leadfeeder";
    case 450: return "LocationIQ";
    case 510: return "Loginradius";
    case 715: return "MadKudu";
    case 228: return "Mailerlite";
    default: return NULL;
    }
}
