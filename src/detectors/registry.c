/* SPDX-License-Identifier: AGPL-3.0-only */
#include "detectors.h"

#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

int br_npmtokenv2_init(const br_detector **out, char **error)
{
    return br_npmtoken_v2_init(out, error);
}

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
    br_nicereply_init,
    br_nimble_init,
    br_oanda_init,
    br_noticeable_init,
    br_nozbeteams_init,
    br_notion_init,
    br_openuv_init,
    br_owlbot_init,
    br_meaningcloud_init,
    br_openweather_init,
    br_pixabay_init,
    br_positionstack_init,
    br_jwt_init,
    br_nvapi_init,
    br_pdfshift_init,
    br_pdflayer_init,
    br_percy_init,
    br_pipedrive_init,
    br_postman_init,
    br_rawg_init,
    br_rebrandly_init,
    br_podio_init,
    br_vpnapi_init,
    br_tomtom_init,
    br_theoddsapi_init,
    br_wistia_init,
    br_uplead_init,
    br_vbout_init,
    br_rapidapi_init,
    br_prefect_init,
    br_sendinbluev2_init,
    br_paydirtapp_init,
    br_scrapeowl_init,
    br_unsplash_init,
    br_stockdata_init,
    br_verimail_init,
    br_route4me_init,
    br_polygon_init,
    br_sportsmonk_init,
    br_yandex_init,
    br_magnetic_init,
    br_signupgenius_init,
    br_veriphone_init,
    br_splunkobservabilitytoken_init,
    br_uptimerobot_init,
    br_urlscan_init,
    br_pollsapi_init,
    br_simplesat_init,
    br_stormglass_init,
    br_workstack_init,
    br_purestake_init,
    br_stormboard_init,
    br_pepipost_init,
    br_nylas_init,
    br_tyntec_init,
    br_scalewaykey_init,
    br_scrutinizerci_init,
    br_securitytrails_init,
    br_versioneye_init,
    br_postageapp_init,
    br_salesblink_init,
    br_rocketreach_init,
    br_vyte_init,
    br_ubidots_init,
    br_rubygems_init,
    br_statuspal_init,
    br_skrappio_init,
    br_timecamp_init,
    br_pushbulletapikey_init,
    br_tatumio_init,
    br_nugetapikey_init,
    br_pagarme_init,
    br_pagerdutyapikey_init,
    br_pandadoc_init,
    br_pandascore_init,
    br_npmtoken_v1_init,
    br_npmtokenv2_init,
    br_okta_init,
    br_omnisend_init,
    br_onedesk_init,
    br_paperform_init,
    br_paralleldots_init,
    br_parsehub_init,
    br_parsers_init,
    br_posthog_init,
    br_postmark_init,
    br_powrbot_init,
    br_prodpad_init,
    br_paymongo_init,
    br_paypaloauth_init,
    br_paystack_init,
    br_peopledatalabs_init,
    br_pipedream_init,
    br_pivotaltracker_init,
    br_plaidkey_init,
    br_planetscale_init,
    br_partnerstack_init,
    br_paymoapp_init,
    br_oopspam_init,
    br_photoroom_init,
    br_opencagedata_init,
    br_mailchimp_init,
    br_numverify_init,
    br_serval_init,
    br_mailgun_init,
    br_mandrill_init,
    br_manifest_init,
    br_marketstack_init,
    br_mattermostpersonaltoken_init,
    br_mongodb_init,
    br_nutritionix_init,
    br_octopusdeploy_init,
    br_onelogin_init,
    br_openai_init,
    br_openaiadmin_init,
    br_openrouter_init,
    br_openvpn_init,
    br_opsgenie_init,
    br_optimizely_init,
    br_overloop_init,
    br_parseur_init,
    br_pastebin_init,
    br_pganalyzereadkey_init,
    br_phraseaccesstoken_init,
    br_pinata_init,
    br_pinecone_init,
    br_planviewleankit_init,
    br_planyo_init,
    br_plivo_init,
    br_poloniex_init,
    br_portainer_init,
    br_portainertoken_init,
    br_postbacks_init,
    br_postgres_init,
    br_privacy_init,
    br_privatekey_init,
    br_prospectcrm_init,
    br_protocolsio_init,
    br_proxycrawl_init,
    br_pubnubpublishkey_init,
    br_pubnubsubscriptionkey_init,
    br_pulumi_init,
    br_pusherchannelkey_init,
    br_pypi_init,
    br_qase_init,
    br_qualaroo_init,
    br_qubole_init,
    br_rabbitmq_init,
    br_railwayapp_init,
    br_ramp_init,
    br_raven_init,
    br_razorpay_init,
    br_reachmail_init,
    br_readme_init,
    br_reallysimplesystems_init,
    br_rechargepayments_init,
    br_redhatpyxis_init,
    br_redis_init,
    br_refiner_init,
    br_rentman_init,
    br_repairshopr_init,
    br_replicate_init,
    br_replyio_init,
    br_requestfinance_init,
    br_restpackhtmltopdfapi_init,
    br_restpackscreenshotapi_init,
    br_rev_init,
    br_revampcrm_init,
    br_ringcentral_init,
    br_ritekit_init,
    br_roaring_init,
    br_robinhoodcrypto_init,
    br_rootly_init,
    br_rownd_init,
    br_runrunit_init,
    br_saladcloudapikey_init,
    br_salescookie_init,
    br_salesflare_init,
    br_salesforce_init,
    br_salesforceoauth2_init,
    br_salesforcerefreshtoken_init,
    br_salesmate_init,
    br_sanity_init,
    br_satismeterprojectkey_init,
    br_satismeterwritekey_init,
    br_saucelabs_init,
    br_scalr_init,
    br_scraperapi_init,
    br_scraperbox_init,
    br_scrapestack_init,
    br_scrapfly_init,
    br_scrapingant_init,
    br_scrapingbee_init,
    br_screenshotapi_init,
    br_screenshotlayer_init,
    br_segmentapikey_init,
    br_selectpdf_init,
    br_semaphore_init,
    br_sendbird_init,
    br_sendbirdorganizationapi_init,
    br_sendgrid_init,
    br_sentryorgtoken_init,
    br_sentrytoken_v1_init,
    br_sentrytoken_v2_init,
    br_serphouse_init,
    br_serpstack_init,
    br_sheety_init,
    br_sherpadesk_init,
    br_shipday_init,
    br_shippo_init,
    br_shodankey_init,
    br_shopify_init,
    br_shopifyoauth_init,
    br_shortcut_init,
    br_shotstack_init,
    br_shutterstock_init,
    br_shutterstockoauth_init,
    br_signable_init,
    br_signalwire_init,
    br_signaturit_init,
    br_sigopt_init,
    br_simfin_init,
    br_simplynoted_init,
    br_simvoly_init,
    br_sinchmessage_init,
    br_sirv_init,
    br_siteleaf_init,
    br_skybiometry_init,
    br_slack_init,
    br_slackwebhook_init,
    br_smartsheets_init,
    br_smartystreets_init,
    br_smooch_init,
    br_snipcart_init,
    br_snowflake_init,
    br_snykkey_init,
    br_solarwindsobservability_init,
    br_sonarcloud_v1_init,
    br_sonarcloud_v2_init,
    br_sourcegraph_init,
    br_sourcegraphcody_init,
    br_sparkpost_init,
    br_spectralops_init,
    br_speechtextai_init,
    br_spoonacular_init,
    br_spotifykey_init,
    br_sqlserver_init,
    br_square_init,
    br_squareapp_init,
    br_squarespace_init,
    br_sslmate_init,
    br_statuscake_init,
    br_statuspage_init,
    br_stitchdata_init,
    br_storecove_init,
    br_storyblok_init,
    br_storyblokpersonalaccesstoken_init,
    br_storychief_init,
    br_strava_init,
    br_streak_init,
    br_stripe_init,
    br_stripepaymentintent_init,
    br_stripo_init,
    br_stytch_init,
    br_sugester_init,
    br_sumologickey_init,
    br_supabasetoken_init,
    br_supernotesapi_init,
    br_surveyanyplace_init,
    br_surveybot_init,
    br_surveysparrow_init,
    br_survicate_init,
    br_swell_init,
    br_swiftype_init,
    br_tableau_init,
    br_tailscale_init,
    br_tallyfy_init,
    br_taxjar_init,
    br_teamgate_init,
    br_teamworkcrm_init,
    br_teamworkdesk_init,
    br_teamworkspaces_init,
    br_technicalanalysisapi_init,
    br_tefter_init,
    br_telegrambottoken_init,
    br_teletype_init,
    br_telnyx_init,
    br_terraformcloudpersonaltoken_init,
    br_testingbot_init,
    br_textmagic_init,
    br_thinkific_init,
    br_thousandeyes_init,
    br_ticketmaster_init,
    br_tickettailor_init,
    br_tiingo_init,
    br_timezoneapi_init,
    br_tineswebhook_init,
    br_tly_init,
    br_tmetric_init,
    br_todoist_init,
    br_toggltrack_init,
    br_tokeet_init,
    br_tomorrowio_init,
    br_tradier_init,
    br_transferwise_init,
    br_travelpayouts_init,
    br_travisci_init,
    br_trelloapikey_init,
    br_tru_init,
    br_trufflehogenterprise_init,
    br_twelvedata_init,
    br_twilio_init,
    br_twilioapikey_init,
    br_twist_init,
    br_twitch_init,
    br_twitchaccesstoken_init,
    br_twitter_v1_init,
    br_twitter_v2_init,
    br_twitterconsumerkey_init,
    br_typeform_v1_init,
    br_typeform_v2_init,
    br_typetalk_init,
    br_uclassify_init,
    br_unifyid_init,
    br_unplugg_init,
    br_upcdatabase_init,
    br_uploadcare_init,
    br_upwave_init,
    br_uri_init,
    br_user_init,
    br_userflow_init,
    br_userstack_init,
    br_vagrantcloudpersonaltoken_init,
    br_vatlayer_init,
    br_vercel_init,
    br_verifier_init,
    br_viewneo_init,
    br_virustotal_init,
    br_visualcrossing_init,
    br_voiceflow_init,
    br_voicegain_init,
    br_voodoosms_init,
    br_vouchery_init,
    br_vultrapikey_init,
    br_walkscore_init,
    br_weatherbit_init,
    br_weatherstack_init,
    br_web3storage_init,
    br_webex_init,
    br_webexbot_init,
    br_webflow_init,
    br_webscraper_init,
    br_webscraping_init,
    br_websitepulse_init,
    br_weightsandbiases_v1_init,
    br_weightsandbiases_v2_init,
    br_wepay_init,
    br_whoxy_init,
    br_wit_init,
    br_wiz_init,
    br_worksnaps_init,
    br_worldcoinindex_init,
    br_worldweather_init,
    br_wrike_init,
    br_xai_init,
    br_yelp_init,
    br_youneedabudget_init,
    br_yousign_init,
    br_youtubeapikey_init,
    br_zapierwebhook_init,
    br_zendeskapi_init,
    br_zenkitapi_init,
    br_zenrows_init,
    br_zenscrape_init,
    br_zenserp_init,
    br_zeplin_init,
    br_zerobounce_init,
    br_zerotier_init,
    br_zipapi_init,
    br_zipbooks_init,
    br_zipcodeapi_init,
    br_zipcodebase_init,
    br_zohocrm_init,
    br_zonkafeedback_init,
    br_zulipchat_init,
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
        case 1078: {
            if (detector->version != 0) return false;
            /* PR #5528 enables Serval in OSS main, not package-zero state. */
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "ServalDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
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
        case 1056: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "OctopusDeployDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1057: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "OpenRouterDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1054: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "PgAnalyzeReadKeyDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1049: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "PineconeDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1055: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "RedHatPyxisDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 368: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "RevDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1060: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "ShippoDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1069: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "SolarwindsDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 767: {
            if (detector->version == 1) return true;
            if (detector->version != 2) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "SonarCloudV2DetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 586: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "TlyDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 274: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "UserDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 1005: {
            if (detector->version == 1) return true;
            if (detector->version != 2) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "WeightsAndBiasesV2DetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 817: {
            if (detector->version != 0) return false;
            if (!feature_flags) return true;
            if (!json_object_is_type(feature_flags, json_type_object)) return false;
            br_json *enabled = NULL;
            if (!json_object_object_get_ex(feature_flags, "WitDetectorEnabled", &enabled)) return true;
            return json_object_is_type(enabled, json_type_boolean) && json_object_get_boolean(enabled);
        }
        case 87: return detector->version == 1 || detector->version == 2;
        case 676: return detector->version == 1 || detector->version == 2;
        case 370: return detector->version == 1 || detector->version == 2;
        case 9: case 113: return detector->version >= 1 && detector->version <= 3;
        case 3: case 4: case 8: case 19: case 107: case 142: case 190: case 303: case 333: case 394: case 430: case 708: case 921: case 994: case 1008: case 120: case 74: case 114: case 49: case 96: return detector->version == 1 || detector->version == 2;
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
        case 853: case 296: case 140: case 573: case 740: case 760: case 935: case 328: case 656: case 111: case 186: case 736: case 272: case 1021: case 1028: case 489: case 991: case 992: case 191: case 841: case 952: case 901: case 668: case 267: case 437: case 177: case 758: case 1000: case 176: case 438: case 735: case 165: case 10: case 774: case 700: case 682: case 669: case 657: case 820: case 753: case 246: case 157: case 995: case 623: case 207: case 896: case 543: case 966: case 121: case 698: case 909: case 261: case 688: case 748: case 216: case 268: case 691: case 531: case 950: case 297: case 737: case 503: case 490: case 129: case 944: case 961: case 50: case 1058: case 1064: case 1065: case 1066: case 1067: case 1068: case 655: case 396: case 797: case 835: case 986: case 273: case 213: case 847: case 481: case 336: case 468: case 104: case 544: case 266: case 635: case 337: case 716: case 134: case 504: case 357: case 622: case 262: case 494: case 535: case 1039: case 997: case 515: case 493: case 912: case 159: case 118: case 305: case 536: case 671: case 291: case 309: case 631: case 780: case 332: case 846: case 99: case 918: case 86:
    case 793: case 547: case 472: case 471: case 143: case 546: case 242: case 470:
    case 279: case 240: case 593: case 550: case 128: case 782:
    case 583: case 850: case 232: case 308: case 292: case 576: case 787: case 117: case 617:
    case 321: case 85: case 766: case 413: case 638: case 575: case 252: case 331:
    case 616: case 178: case 200: case 776: case 245: case 778: case 124: case 445:
    case 916: case 985: case 32: case 298: case 731: case 21: case 205: case 601: case 791: case 479: case 803: case 765: case 161: case 81: case 243: case 842: case 534: case 31: case 77: case 658: case 724: case 23: case 79: case 195: case 545: case 699: case 410: case 1038: case 533: case 20: case 439:
        case 34: case 172: case 363: case 174: case 895: case 364: case 22: case 201: case 1040: case 945:
        case 875: case 595: case 965: case 837: case 492: case 1037: case 755: case 734: case 614: case 80:
        case 516: case 942: case 943: case 822: case 968: case 938: case 15: case 275: case 411: case 440:
        case 82: case 83: case 914: case 84: case 998: case 761: case 229: case 577: case 903: case 999:
        case 934: case 11: case 814: case 495: case 276: case 818: case 900: case 288: case 836: case 702:
        case 967: case 956: case 964: case 517: case 518: case 299: case 422: case 461: case 480: case 996:
        case 1035: case 673: case 369: case 1001: case 300: case 217: case 925: case 47: case 1031: case 868:
        case 1012: case 230: case 231: case 398: case 852: case 412: case 559: case 581: case 660: case 560:
        case 139: case 451: case 537: case 122: case 641: case 609: case 750: case 751: case 12: case 1017:
        case 613: case 561: case 469: case 690: case 625: case 88: case 902: case 1044: case 587: case 674:
        case 462: case 519: case 785: case 611: case 594: case 704: case 851: case 661: case 203: case 162:
        case 725: case 263: case 520: case 13: case 30: case 247: case 562: case 608: case 505: case 927:
        case 89: case 928: case 936: case 1051: case 849: case 345: case 898: case 14: case 25: case 264:
        case 109: case 795: case 775: case 591: case 624: case 222: case 1016: case 340: case 476: case 549:
        case 16: case 1027: case 955: case 538: case 705: case 123: case 915: case 718: case 233: case 234:
        case 202: case 204: case 365: case 675: case 1034: case 929: case 719: case 151: case 319: case 628:
        case 629: case 630: case 582: case 826: case 91: case 777: case 610: case 93: case 759: case 612:
        case 589: case 640: case 563: case 840: case 421: case 289: case 913: case 446: case 339: case 864:
        case 414: case 372: case 832: case 662: case 29: case 94: case 922: case 137: case 26: case 1011:
        case 827: case 310: case 1010: case 989: case 809: case 871: case 606: case 539: case 540: case 722:
        case 679: case 17: case 779: case 541: case 946: case 496: case 160: case 373: case 706: case 497:
        case 419: case 937: case 417: case 810: case 374: case 116: case 475: case 597: case 452: case 930:
        case 101: case 1033: case 218: case 663: case 551: case 870: case 482: case 984: case 687: case 415:
        case 483: case 248: case 1023: case 799: case 464: case 342: case 46: case 95: case 720: case 824:
        case 552: case 553: case 155: case 144: case 948: case 599: case 600: case 441: case 825: case 1006:
        case 236: case 811:
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
    case 544: return "Nicereply";
    case 266: return "Nimble";
    case 635: return "Oanda";
    case 337: return "Noticeable";
    case 716: return "NozbeTeams";
    case 134: return "Notion";
    case 504: return "Openuv";
    case 357: return "Owlbot";
    case 622: return "MeaningCloud";
    case 262: return "OpenWeather";
    case 494: return "Pixabay";
    case 535: return "PositionStack";
    case 1039: return "JWT";
    case 997: return "NVAPI";
    case 515: return "PdfShift";
    case 493: return "PdfLayer";
    case 912: return "Percy";
    case 159: return "Pipedrive";
    case 118: return "Postman";
    case 305: return "Rawg";
    case 536: return "Rebrandly";
    case 671: return "Podio";
    case 291: return "Vpnapi";
    case 309: return "Tomtom";
    case 631: return "TheOddsApi";
    case 780: return "Wistia";
    case 332: return "Uplead";
    case 846: return "Vbout";
    case 99: return "RapidApi";
    case 918: return "Prefect";
    case 86: return "SendinBlueV2";
    case 793: return "Paydirtapp";
    case 547: return "Scrapeowl";
    case 472: return "Unsplash";
    case 471: return "Stockdata";
    case 143: return "Verimail";
    case 546: return "Route4me";
    case 242: return "Polygon";
    case 470: return "Sportsmonk";
    case 279: return "Yandex";
    case 240: return "Magnetic";
    case 593: return "Signupgenius";
    case 550: return "Veriphone";
    case 128: return "SplunkOberservabilityToken";
    case 782: return "UptimeRobot";
    case 583: return "Urlscan";
    case 850: return "PollsAPI";
    case 232: return "Simplesat";
    case 308: return "Stormglass";
    case 292: return "Workstack";
    case 576: return "PureStake";
    case 787: return "Stormboard";
    case 117: return "Pepipost";
    case 617: return "Nylas";
    case 321: return "Tyntec";
    case 85: return "ScalewayKey";
    case 766: return "ScrutinizerCi";
    case 413: return "SecurityTrails";
    case 638: return "VersionEye";
    case 575: return "PostageApp";
    case 252: return "Salesblink";
    case 331: return "RocketReach";
    case 616: return "Vyte";
    case 178: return "Ubidots";
    case 200: return "RubyGems";
    case 776: return "Statuspal";
    case 245: return "Skrappio";
    case 778: return "TimeCamp";
    case 124: return "PushBulletApiKey";
    case 445: return "TatumIO";
    case 916: return "NuGetApiKey";
    case 985: return "Pagarme";
    case 32: return "PagerDutyApiKey";
    case 298: return "Pandadoc";
    case 731: return "PandaScore";
    case 49: return "NpmToken";
    case 21: return "Okta";
    case 205: return "Omnisend";
    case 601: return "Onedesk";
    case 791: return "Paperform";
    case 479: return "ParallelDots";
    case 803: return "Parsehub";
    case 765: return "Parsers";
    case 161: return "PosthogApp";
    case 81: return "Postmark";
    case 243: return "Powrbot";
    case 842: return "Prodpad";
    case 534: return "Paymongo";
    case 31: return "PaypalOauth";
    case 77: return "Paystack";
    case 658: return "PeopleDataLabs";
    case 724: return "Pipedream";
    case 23: return "PivotalTracker";
    case 79: return "PlaidKey";
    case 195: return "PlanetScale";
    case 545: return "Partnerstack";
    case 699: return "Paymoapp";
    case 410: return "OOPSpam";
    case 1038: return "Photoroom";
    case 533: return "OpenCageData";
    case 20: return "Mailchimp";
    case 439: return "Numverify";
    case 34: return "Mailgun";
    case 172: return "Mandrill";
    case 644: return "Manifest";
    case 363: return "Marketstack";
    case 174: return "MattermostPersonalToken";
    case 895: return "MongoDB";
    case 364: return "Nutritionix";
    case 1056: return "OctopusDeploy";
    case 22: return "OneLogin";
    case 201: return "OpenAI";
    case 1040: return "OpenAIAdmin";
    case 1057: return "OpenRouter";
    case 945: return "OpenVpn";
    case 875: return "Opsgenie";
    case 595: return "Optimizely";
    case 965: return "Overloop";
    case 837: return "Parseur";
    case 492: return "Pastebin";
    case 1054: return "PgAnalyzeReadKey";
    case 1037: return "PhraseAccessToken";
    case 755: return "Pinata";
    case 1049: return "Pinecone";
    case 734: return "PlanviewLeanKit";
    case 614: return "Planyo";
    case 80: return "Plivo";
    case 516: return "Poloniex";
    case 942: return "Portainer";
    case 943: return "PortainerToken";
    case 822: return "Postbacks";
    case 968: return "Postgres";
    case 938: return "Privacy";
    case 15: return "PrivateKey";
    case 275: return "ProspectCRM";
    case 411: return "ProtocolsIO";
    case 440: return "ProxyCrawl";
    case 82: return "PubNubPublishKey";
    case 83: return "PubNubSubscriptionKey";
    case 914: return "Pulumi";
    case 84: return "PusherChannelKey";
    case 998: return "PyPI";
    case 761: return "Qase";
    case 229: return "Qualaroo";
    case 577: return "Qubole";
    case 903: return "RabbitMQ";
    case 999: return "RailwayApp";
    case 934: return "Ramp";
    case 330: return "Raven";
    case 11: return "RazorPay";
    case 814: return "Reachmail";
    case 495: return "ReadMe";
    case 276: return "ReallySimpleSystems";
    case 818: return "RechargePayments";
    case 1055: return "RedHatPyxis";
    case 900: return "Redis";
    case 288: return "Refiner";
    case 836: return "Rentman";
    case 702: return "Repairshopr";
    case 967: return "Replicate";
    case 956: return "ReplyIO";
    case 964: return "RequestFinance";
    case 517: return "RestpackHtmlToPdfAPI";
    case 518: return "RestpackScreenshotAPI";
    case 368: return "Rev";
    case 299: return "RevampCRM";
    case 422: return "RingCentral";
    case 461: return "RiteKit";
    case 480: return "Roaring";
    case 996: return "RobinhoodCrypto";
    case 1035: return "Rootly";
    case 673: return "Rownd";
    case 369: return "RunRunIt";
    case 1001: return "SaladCloudApiKey";
    case 300: return "Salescookie";
    case 217: return "Salesflare";
    case 925: return "Salesforce";
    case 47: return "SalesforceOauth2";
    case 1031: return "SalesforceRefreshToken";
    case 868: return "Salesmate";
    case 1012: return "Sanity";
    case 230: return "SatismeterProjectkey";
    case 231: return "SatismeterWritekey";
    case 398: return "SauceLabs";
    case 852: return "Scalr";
    case 412: return "ScraperAPI";
    case 559: return "ScraperBox";
    case 581: return "ScrapeStack";
    case 660: return "Scrapfly";
    case 560: return "ScrapingAnt";
    case 139: return "ScrapingBee";
    case 451: return "ScreenshotAPI";
    case 537: return "ScreenshotLayer";
    case 122: return "SegmentApiKey";
    case 641: return "SelectPDF";
    case 609: return "Semaphore";
    case 750: return "Sendbird";
    case 751: return "SendbirdOrganizationAPI";
    case 12: return "SendGrid";
    case 1017: return "SentryOrgToken";
    case 87: return "SentryToken";
    case 613: return "Serphouse";
    case 561: return "SerpStack";
    case 1078: return "Serval";
    case 469: return "Sheety";
    case 690: return "Sherpadesk";
    case 625: return "Shipday";
    case 1060: return "Shippo";
    case 88: return "ShodanKey";
    case 902: return "Shopify";
    case 1044: return "ShopifyOAuth";
    case 587: return "Shortcut";
    case 674: return "Shotstack";
    case 462: return "Shutterstock";
    case 519: return "ShutterstockOAuth";
    case 785: return "Signable";
    case 611: return "Signalwire";
    case 594: return "Signaturit";
    case 704: return "Sigopt";
    case 851: return "SimFin";
    case 661: return "SimplyNoted";
    case 203: return "Simvoly";
    case 162: return "SinchMessage";
    case 725: return "Sirv";
    case 263: return "Siteleaf";
    case 520: return "SkyBiometry";
    case 13: return "Slack";
    case 30: return "SlackWebhook";
    case 247: return "Smartsheets";
    case 562: return "SmartyStreets";
    case 608: return "Smooch";
    case 505: return "Snipcart";
    case 927: return "Snowflake";
    case 89: return "SnykKey";
    case 1069: return "SolarWindsObservability";
    case 767: return "SonarCloud";
    case 928: return "Sourcegraph";
    case 936: return "SourcegraphCody";
    case 183: return "Sparkpost";
    case 1051: return "SpectralOps";
    case 849: return "SpeechTextAI";
    case 345: return "Spoonacular";
    case 90: return "SpotifyKey";
    case 898: return "SQLServer";
    case 14: return "Square";
    case 25: return "SquareApp";
    case 264: return "Squarespace";
    case 109: return "SslMate";
    case 795: return "Statuscake";
    case 775: return "Statuspage";
    case 591: return "Stitchdata";
    case 624: return "Storecove";
    case 222: return "StoryblokAccessToken";
    case 1016: return "StoryblokPersonalAccessToken";
    case 340: return "Storychief";
    case 476: return "Strava";
    case 549: return "Streak";
    case 16: return "Stripe";
    case 1027: return "StripePaymentIntent";
    case 955: return "Stripo";
    case 538: return "Stytch";
    case 705: return "Sugester";
    case 123: return "SumoLogicKey";
    case 915: return "SupabaseToken";
    case 718: return "SuperNotesAPI";
    case 233: return "SurveyAnyplace";
    case 234: return "SurveyBot";
    case 202: return "SurveySparrow";
    case 204: return "Survicate";
    case 365: return "Swell";
    case 675: return "Swiftype";
    case 1034: return "TableauPersonalAccessToken";
    case 929: return "Tailscale";
    case 719: return "Tallyfy";
    case 151: return "Taxjar";
    case 319: return "Teamgate";
    case 628: return "TeamworkCRM";
    case 629: return "TeamworkDesk";
    case 630: return "TeamworkSpaces";
    case 582: return "TechnicalAnalysisApi";
    case 826: return "Tefter";
    case 91: return "TelegramBotToken";
    case 777: return "Teletype";
    case 610: return "Telnyx";
    case 93: return "TerraformCloudPersonalToken";
    case 759: return "TestingBot";
    case 612: return "Textmagic";
    case 589: return "Thinkific";
    case 640: return "ThousandEyes";
    case 563: return "TicketMaster";
    case 840: return "Tickettailor";
    case 421: return "Tiingo";
    case 289: return "Timezoneapi";
    case 913: return "TinesWebhook";
    case 586: return "TLy";
    case 446: return "Tmetric";
    case 339: return "Todoist";
    case 290: return "TogglTrack";
    case 864: return "Tokeet";
    case 414: return "TomorrowIO";
    case 372: return "Tradier";
    case 832: return "Transferwise";
    case 662: return "TravelPayouts";
    case 29: return "TravisCI";
    case 94: return "TrelloApiKey";
    case 605: return "Tru";
    case 922: return "TrufflehogEnterprise";
    case 137: return "TwelveData";
    case 26: return "Twilio";
    case 1011: return "TwilioApiKey";
    case 827: return "Twist";
    case 310: return "Twitch";
    case 1010: return "TwitchAccessToken";
    case 676: return "Twitter";
    case 989: return "TwitterConsumerkey";
    case 370: return "Typeform";
    case 809: return "Typetalk";
    case 871: return "Uclassify";
    case 606: return "UnifyID";
    case 539: return "Unplugg";
    case 540: return "UPCDatabase";
    case 722: return "UploadCare";
    case 679: return "Upwave";
    case 17: return "URI";
    case 274: return "User";
    case 779: return "Userflow";
    case 541: return "UserStack";
    case 946: return "VagrantCloudPersonalToken";
    case 496: return "VatLayer";
    case 160: return "Vercel";
    case 373: return "Verifier";
    case 706: return "Viewneo";
    case 497: return "VirusTotal";
    case 419: return "VisualCrossing";
    case 937: return "Voiceflow";
    case 417: return "Voicegain";
    case 810: return "VoodooSMS";
    case 374: return "Vouchery";
    case 116: return "VultrApiKey";
    case 475: return "WalkScore";
    case 597: return "WeatherBit";
    case 452: return "WeatherStack";
    case 930: return "Web3Storage";
    case 101: return "Webex";
    case 1033: return "WebexBot";
    case 218: return "Webflow";
    case 663: return "WebScraper";
    case 551: return "Webscraping";
    case 870: return "Websitepulse";
    case 1005: return "WeightsAndBiases";
    case 194: return "WePay";
    case 482: return "Whoxy";
    case 817: return "Wit";
    case 984: return "Wiz";
    case 687: return "Worksnaps";
    case 415: return "WorldCoinIndex";
    case 483: return "WorldWeather";
    case 248: return "Wrike";
    case 1023: return "XAI";
    case 799: return "Yelp";
    case 464: return "YouNeedABudget";
    case 342: return "YouSign";
    case 46: return "YoutubeApiKey";
    case 45: return "ZapierWebhook";
    case 95: return "ZendeskApi";
    case 720: return "ZenkitAPI";
    case 824: return "ZenRows";
    case 552: return "Zenscrape";
    case 553: return "Zenserp";
    case 155: return "Zeplin";
    case 144: return "Zerobounce";
    case 948: return "ZeroTier";
    case 599: return "ZipAPI";
    case 600: return "ZipBooks";
    case 441: return "ZipCodeAPI";
    case 825: return "Zipcodebase";
    case 1006: return "ZohoCRM";
    case 236: return "ZonkaFeedback";
    case 811: return "ZulipChat";
    case 329: return "Leadfeeder";
    case 450: return "LocationIQ";
    case 510: return "Loginradius";
    case 715: return "MadKudu";
    case 228: return "Mailerlite";
    default: return NULL;
    }
}
