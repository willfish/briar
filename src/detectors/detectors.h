/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef BRIAR_DETECTORS_H
#define BRIAR_DETECTORS_H

#include "briar.h"

/* Named factories initialize private regex state before scan workers start. */
int br_abstract_init(const br_detector **out, char **error);
int br_abuseipdb_init(const br_detector **out, char **error);
int br_abyssale_init(const br_detector **out, char **error);
int br_adafruitio_init(const br_detector **out, char **error);
int br_accuweather_v1_init(const br_detector **out, char **error);
int br_accuweather_v2_init(const br_detector **out, char **error);
int br_adobeio_init(const br_detector **out, char **error);
int br_adzuna_init(const br_detector **out, char **error);
int br_aeroworkflow_init(const br_detector **out, char **error);
int br_agora_init(const br_detector **out, char **error);
int br_aha_init(const br_detector **out, char **error);
int br_airbrakeprojectkey_init(const br_detector **out, char **error);
int br_airbrakeuserkey_init(const br_detector **out, char **error);
int br_airship_init(const br_detector **out, char **error);
int br_airtableoauth_init(const br_detector **out, char **error);
int br_airtablepersonalaccesstoken_init(const br_detector **out, char **error);
int br_airvisual_init(const br_detector **out, char **error);
int br_aiven_init(const br_detector **out, char **error);
int br_alchemy_init(const br_detector **out, char **error);
int br_alconost_init(const br_detector **out, char **error);
int br_alegra_init(const br_detector **out, char **error);
int br_aletheiaapi_init(const br_detector **out, char **error);
int br_algoliaadminkey_init(const br_detector **out, char **error);
int br_alibaba_init(const br_detector **out, char **error);
int br_alienvault_init(const br_detector **out, char **error);
int br_allsports_init(const br_detector **out, char **error);
int br_amadeus_init(const br_detector **out, char **error);
int br_ambee_init(const br_detector **out, char **error);
int br_amplitudeapikey_init(const br_detector **out, char **error);
int br_anthropic_init(const br_detector **out, char **error);
int br_anypoint_init(const br_detector **out, char **error);
int br_anypointoauth2_init(const br_detector **out, char **error);
int br_apacta_init(const br_detector **out, char **error);
int br_api2cart_init(const br_detector **out, char **error);
int br_apideck_init(const br_detector **out, char **error);
int br_apiflash_init(const br_detector **out, char **error);
int br_apifonica_init(const br_detector **out, char **error);
int br_apify_init(const br_detector **out, char **error);
int br_apilayer_init(const br_detector **out, char **error);
int br_apimatic_init(const br_detector **out, char **error);
int br_apimetrics_init(const br_detector **out, char **error);
int br_apitemplate_init(const br_detector **out, char **error);
int br_apollo_init(const br_detector **out, char **error);
int br_appcues_init(const br_detector **out, char **error);
int br_appfollow_init(const br_detector **out, char **error);
int br_appointedd_init(const br_detector **out, char **error);
int br_appsynergy_init(const br_detector **out, char **error);
int br_apptivo_init(const br_detector **out, char **error);
int br_artifactory_init(const br_detector **out, char **error);
int br_artifactoryreferencetoken_init(const br_detector **out, char **error);
int br_artsy_init(const br_detector **out, char **error);
int br_asanaoauth_init(const br_detector **out, char **error);
int br_asanapersonalaccesstoken_init(const br_detector **out, char **error);
int br_assemblyai_init(const br_detector **out, char **error);
int br_atera_init(const br_detector **out, char **error);
int br_atlassian_v1_init(const br_detector **out, char **error);
int br_atlassian_v2_init(const br_detector **out, char **error);
int br_bitbucketdatacenter_init(const br_detector **out, char **error);
int br_confluencedatacenter_init(const br_detector **out, char **error);
int br_jiradatacenterpat_init(const br_detector **out, char **error);
int br_audd_init(const br_detector **out, char **error);
int br_auth0managementapitoken_init(const br_detector **out, char **error);
int br_auth0oauth_init(const br_detector **out, char **error);
int br_autodesk_init(const br_detector **out, char **error);
int br_autoklose_init(const br_detector **out, char **error);
int br_autopilot_init(const br_detector **out, char **error);
int br_avazapersonalaccesstoken_init(const br_detector **out, char **error);
int br_aviationstack_init(const br_detector **out, char **error);
int br_aws_access_keys_init(const br_detector **out, char **error);
int br_aws_appsync_init(const br_detector **out, char **error);
int br_aws_session_keys_init(const br_detector **out, char **error);
int br_axonaut_init(const br_detector **out, char **error);
int br_aylien_init(const br_detector **out, char **error);
int br_ayrshare_init(const br_detector **out, char **error);
int br_azure_batch_init(const br_detector **out, char **error);
int br_azure_cosmosdb_init(const br_detector **out, char **error);
int br_azure_entra_refreshtoken_init(const br_detector **out, char **error);
int br_azure_entra_serviceprincipal_v1_init(const br_detector **out, char **error);
int br_azure_entra_serviceprincipal_v2_init(const br_detector **out, char **error);
int br_azure_openai_init(const br_detector **out, char **error);
int br_azure_storage_init(const br_detector **out, char **error);
int br_azureapimanagement_repositorykey_init(const br_detector **out, char **error);

#endif
