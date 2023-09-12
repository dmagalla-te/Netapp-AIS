#!/bin/bash

# Written by ThousandEyes Professional Services.
# Email: services@thousandeyes.com
# License is covered under the existing MSA agreement between customer and ThousandEyes

# This script will facilitate the installation and configuration of the Alert Integration Service.

# parameters for retrieving build
ACTION=$1
MIB_FILE="THOUSANDEYES-ALARM-SNMP-MIB.txt"

# general parameters for AIS operation
API_POLLER_TARGET_WEBHOOK_SERVER_URL="http://localhost:8081/hooks"
API_POLLER_EXECUTION_INTERVAL_MILLISECONDS=120000
API_POLLER_API_CALL_BACKOFF_MILLISECONDS=15000
API_POLLER_API_MAX_RETRIES=50
API_POLLER_API_SOCKET_CONNECT_TIMEOUT_MILLISECONDS=5000
API_POLLER_API_SOCKET_READ_TIMEOUT_MILLISECONDS=5000
API_POLLER_API_TEST_ENDPOINT="https://api.thousandeyes.com/v6/status.json"

# variables to hold the text that will be written to application.yaml
APPLICATION_YAML_TEXT=""
SERVER_STANZA=""
LOGGING_STANZA=""
API_POLLER_GENERAL_STANZA=""
TEST_METRIC_DATA_STANZA=""
ALERT_MONITOR_STANZA=""
EA_MONITOR_STANZA=""
ENDPOINTS_STANZA=""
SERVICES_SECTION=""

# as more endpoints are added to the install script, add them to this array
declare -a AIS_SUPPORTED_ENDPOINTS=("splunk_enterprise" "snmp" "servicenow_incident_management" "servicenow_event_management" "dynatrace")

# local parameters for service definition files
JAVA=`which java`
BASH=`which bash`
AIS_JAR="AlertIntegrationService.jar"

ANSWER=""

# function to create service definiton file - this is what will be provided to systemctl so
# the AIS is
function create_service_definition_file() {
    echo "Creating service definition file..."

    cat << EOF > $WORKING_DIR/alert-integration-service.service
[Unit]
Description=Alert Integration Service

[Service]
WorkingDirectory=$WORKING_DIR
SyslogIdentifier=Alert Integration Service
User=$USER
ExecStart=$BASH -c "$JAVA -jar $WORKING_DIR/$AIS_JAR --spring.config.location=$WORKING_DIR/config/application.yaml"
Type=simple
Restart=always

[Install]
WantedBy=multi-user.target
EOF

}

function create_target_directory() {

    echo ""
    echo "Creating directories (will add on to current contents if they exist): $WORKING_DIR"
    if ! mkdir -p $WORKING_DIR
    then
        echo ""
        echo "Could not create the target directory. Check user permissions and try again."
        exit
    fi

    if ! mkdir -p $WORKING_DIR/log
    then
        echo ""
        echo "Could not create the target directory. Check user permissions and try again."
        exit
    fi

    if ! mkdir -p $WORKING_DIR/config
    then
        echo ""
        echo "Could not create the target directory. Check user permissions and try again."
        exit
    fi

    if ! mkdir -p $WORKING_DIR/data
    then
        echo ""
        echo "Could not create the target directory. Check user permissions and try again."
        exit
    fi
}

function create_server_yaml_stanza () {
    SERVER_STANZA=$(cat << EOF
app:
  version: '@project.version@'

# mail - configure this to enable emails sent when an exception is raised in
# event processing
spring:
  mail:
    enabled: false
    host:
    username:
    password:
    properties:
      mail:
        transport:
          protocol: smtp
        smtp:
          port: 587
          auth: true
          starttls:
            enable: true
            required: true
        to:
        from:

serverMonitoring:
  emailNotificationCooldown: 3600

server:
  port: 8081

EOF
)
SERVER_STANZA="$SERVER_STANZA
"
}

function create_logging_yaml_stanza () {
    LOGGING_STANZA=$(cat << EOF

logging.file.name: log/ais.log
logging.file.max-history: 20
logging.level.com.thousandeyes: DEBUG

EOF
)
LOGGING_STANZA="$LOGGING_STANZA
"
}

function create_api_poller_general_yaml_stanza () {
  include_str=''
  #echo "groups: ${API_POLLER_ACCOUNT_GROUPS}"
  IFS=',' read -a ag_array <<< $API_POLLER_ACCOUNT_GROUPS

  for i in "${ag_array[@]}" ; do
    # remove leading spaces
    j=`echo $i | xargs`
    include_str+="        - $j\n"
  done


    API_POLLER_GENERAL_STANZA=$(cat << EOF

teapipoller:
  general-parameters:
    runApiPoller: $API_POLLER_RUN_APP
    targetWebhookServerUrl: $API_POLLER_TARGET_WEBHOOK_SERVER_URL
    executionInterval: $API_POLLER_EXECUTION_INTERVAL_MILLISECONDS
    apiCallBackoffMs: $API_POLLER_API_CALL_BACKOFF_MILLISECONDS
    apiMaxRetries: $API_POLLER_API_MAX_RETRIES
    apiSocketConnectTimeoutMs: $API_POLLER_API_SOCKET_CONNECT_TIMEOUT_MILLISECONDS
    apiSocketReadTimeoutMs: $API_POLLER_API_SOCKET_READ_TIMEOUT_MILLISECONDS
    organizationName: $API_POLLER_ORGANIZATION_NAME
    testEndpoint: 'https://api.thousandeyes.com/v6/status.json'
    apiVersion: 'v6'
    username: $API_POLLER_EMAIL
    basicAuthToken: $API_POLLER_BASIC_AUTH_TOKEN
    account-group-configuration:
#      suppressAlertClearWebhooks:
#        - "*-Prod"
#      exclude:
#        - "*-Dev"
      include:
`echo -e "${include_str}"`
EOF
)
}

function create_api_poller_alert_monitor_section () {
    ALERT_MONITOR_STANZA=$(cat << EOF

  queryAlertEndpoint:
    doQueryAlertEndpoint: true
    doMetadataEnrichment: true
    metadataFields: description,type,url,server,prefix,targetAgentId,domain,sipRegistrar
EOF
)
}

function create_api_poller_ea_monitor_section () {
    EA_MONITOR_STANZA=$(cat << EOF

  enterpriseAgentClustersChecks:
    doEnterpriseAgentsClustersCheck: true
    enterpriseAgentClusterOfflineMinutes: 10
    enterpriseAgentCheckIntervalMs: 120000
    agentCacheDataRefreshMs: 360000
EOF
)
}

function create_api_poller_test_metric_data_section () {
    TEST_METRIC_DATA_STANZA=$(cat << EOF

  # applicable to Splunk/Elasticsearch only
  testMetricData:
    doSendTestMetricData: true
    testMetricDataFetchWindow: 15m
    doSendPathVisData: true
    maxRoundIdAgeSeconds: 3600
    metadataFieldsForTestMetrics: description,type,url,server,prefix,targetAgentId,domain,sipRegistrar
    doMetadataEnrichmentForTestMetrics: true
    getWebTransactionDetail: true
    testMetricDataIntervalMs: 600000
    getNormalPathVisualizationData: true
    getDetailedPathVisualizationData: false
EOF
)

}

function create_api_poller_proxy_section () {

    PROXY_STANZA=$(cat << EOF

  proxy:
    enabled: true
    address: $API_POLLER_PROXY_IP_HOST
    port: $API_POLLER_PROXY_PORT
    type: 'http'
EOF
)
}

function create_api_poller_proxy_creds_section () {
    PROXY_CREDS_SECTION=$(cat << EOF

    requiresAuth: true
    credentials:
      username: $API_POLLER_PROXY_USERNAME
      password: $API_POLLER_PROXY_PASSWORD

EOF
)

}

function create_endpoint_yaml_stanza () {
    ENDPOINTS_STANZA=$(cat << EOF

endpoints:
  webhookControllerRequestMappings:
    baseMapping: "/"
    mapping1: "/hooks"
    mapping2: "/"
  transmissionRetry:
    numRetries: 5
    retryTimeout: 30

  # these are the downstream services that we're sending data to.
  # one incoming webhook can be sent to multiple downstream services.
  services:
EOF
)
}

function build_splunk_config_section () {
    echo ""
    echo "Building Splunk configuration..."
    echo ""

    user_input_loop "Enter the Splunk URL (e.g. https://<splunk instance>:8088/services/collector/event): " "WORD"
    WEBHOOK_SERVER_SPLUNK_URL=$ANSWER
    user_input_loop "Enter the HTTP Event Collector (HEC) token: " "WORD"
    WEBHOOK_SERVER_SPLUNK_HEC_TOKEN=$ANSWER

    SPLUNK_SECTION=$(cat << EOF

    - name: splunk
      splunkInstances:
        - token: $WEBHOOK_SERVER_SPLUNK_HEC_TOKEN
          url: $WEBHOOK_SERVER_SPLUNK_URL
          trustAllCerts: true

EOF
)
    SERVICES_SECTION=${SERVICES_SECTION}${SPLUNK_SECTION}

}

function build_snmp_config_section () {
    echo ""
    echo "Building SNMP configuration..."
    echo ""

    while true ; do
      read -p "Enter the version of SNMP to use - v2c or v3: " SNMP_VERSION
      if [[ "$SNMP_VERSION" = "v2c" || "$SNMP_VERSION" = "v3" ]] ; then
        break
      fi
    done

    read -p "Please provide the list of SNMP targets to send traps to (format: [ip or host]/port, e.g. 192.168.1.157/162). Separate multiple entries with commas: " SNMP_TRAP_SINKS


    if [ "$SNMP_VERSION" = "v2c" ]
    then
    read -p "Provide the community string: " COMMUNITY_STRING
    echo

    SNMP_SECTION=$(cat << EOF

    - name: snmp
      snmpVersion: 'v2c'
      snmpTrapSinks: [ $SNMP_TRAP_SINKS ]
      snmpV2CCommunity_ro: '$COMMUNITY_STRING'

      # Uncomment the below to route alerts to different destinations based on
      # whether the prefix is found in the alert rule name - e.g.
      # Alerts with 'TEST' in the rule name will get routed to 192.168.1.170/162
      #
      # If the 'default' section is uncommented, all other alerts that do not contain
      # 'TEST' in the rule name will be sent to 192.168.1.200/162
      #
      # snmpMessageRoutingConfigurations:
      #   - prefix: 'TEST'
      #     destinations: [ '192.168.1.170/162' ]
      #   - default:
      #     destinations: [ '192.168.1.200/162' ]

      # These fields will determine the string value of the Severity field in the SNMP trap
      # on alert triggers and clears. 'EA' represents enterprise agent alerts, while 'Test'
      # represents alerts raised by tests.

      snmpEATriggerSeverity: 'Major'
      snmpEAClearSeverity: 'Clear'
      snmpTestTriggerSeverity: 'Major'
      snmpTestClearSeverity: 'Clear'
      snmpDefaultValueForEmptyField: '0'
EOF
)
    else
    read -p "Provide the security name (e.g. 'username'): " SECURITY_NAME
    read -p "Provide the auth password (e.g. 'auth-password'): " AUTH_PASSWORD
    read -p "Provide the privacy password (e.g. 'priv-password'): " PRIV_PASSWORD
    echo "Note: Check the config/application.yaml to ensure that the right values are set for snmpV3AuthProtocol and snmpV3PrivProtocol."
    echo

    SNMP_SECTION=$(cat << EOF

    - name: snmp
      snmpVersion: 'v3'
      snmpTrapSinks: [ $SNMP_TRAP_SINKS ]

      # Change these as necessary to reflect the correct username and auth/priv passwords.
      # The different auth/priv protocols can be found in the v2 installation/operations guide.
      snmpV3SecurityName: '$SECURITY_NAME'
      snmpV3AuthProtocol: 'AuthHMAC256SHA384'
      snmpV3AuthPassword: '$AUTH_PASSWORD'
      snmpV3PrivProtocol: 'PrivAES256'
      snmpV3PrivPassword: '$PRIV_PASSWORD'

      # Uncomment the below to route alerts to different destinations based on
      # whether the prefix is found in the alert rule name - e.g.
      # Alerts with 'TEST' in the rule name will get routed to 192.168.1.170/162
      #
      # If the 'default' section is uncommented, all other alerts that do not contain
      # 'TEST' in the rule name will be sent to 192.168.1.200/162
      #
      # snmpMessageRoutingConfigurations:
      #   - prefix: 'TEST'
      #     destinations: [ '192.168.1.170/162' ]
      #   - default:
      #     destinations: [ '192.168.1.200/162' ]

      # These fields will determine the string value of the Severity field in the SNMP trap
      # on alert triggers and clears. 'EA' represents enterprise agent alerts, while 'Test'
      # represents alerts raised by tests.

      snmpEATriggerSeverity: 'Major'
      snmpEAClearSeverity: 'Clear'
      snmpTestTriggerSeverity: 'Major'
      snmpTestClearSeverity: 'Clear'
      snmpDefaultValueForEmptyField: '0'
EOF
)
    fi
    SERVICES_SECTION=${SERVICES_SECTION}${SNMP_SECTION}
}

function build_snow_em_config_section () {
    user_input_loop "Enter the hostname of the ServiceNow instance (e.g. dev12345.service-now.com): " "WORD"
    SNOW_EM_INSTANCE_NAME=$ANSWER
    user_input_loop "Enter the username that will be used to create incidents in ServiceNow: " "WORD"
    SNOW_EM_USER=$ANSWER
    read -s -p "Enter the password for this user: " SNOW_EM_PASSWORD

    SNOW_EM_SECTION=$(cat << EOF

    - name: servicenowem
      snowEMUsername: $SNOW_EM_USER
      snowEMPassword: $SNOW_EM_PASSWORD
      snowEMWebhookURL: 'https://$SNOW_EM_INSTANCE_NAME/api/global/em/jsonv2'
      snowEMNodeName: 'ThousandEyes'
      snowEMSourceName: 'ThousandEyes Alert Integration Service'
      snowEMConfigurationTemplate:
      - field: '_severity_on_alert_trigger'
        value: 4

      - field: '_severity_on_alert_clear'
        value: 0

      - field: '_send_additional_info'
        value: true

      - field: 'node'
        value: '__target'

      - field: 'event_class'
        value: '__entityname'

      - field: 'source'
        value: 'ThousandEyes Alert Integration Service'

      - field: 'resource'
        value: '__alertid' #__alertid or freeform text

      - field: 'type'
        value: 'Alert: __alerttype'

      - field: 'metric_name'
        value: '__alerttype'

      - field: 'message_key'
        value: '__alertid'

      - field: 'description'
        value: 'Alert notification __state for __entityname (Rule: __alertrulename) (Target: __target) (Test name: __testname)'
EOF
)
    SERVICES_SECTION=${SERVICES_SECTION}${SNOW_EM_SECTION}
}

function build_snow_im_config_section () {

    user_input_loop "Enter the hostname of the ServiceNow instance (e.g. dev12345.service-now.com): " "WORD"
    SNOW_IM_INSTANCE_NAME=$ANSWER
    user_input_loop "Enter the username that will be used to create incidents in ServiceNow: " "WORD"
    SNOW_IM_USER=$ANSWER
    read -s -p "Enter the password for this user: " SNOW_IM_PASSWORD

    SNOW_IM_SECTION=$(cat << EOF

    - name: servicenow
      snowWebhookUrl: 'https://$SNOW_IM_INSTANCE_NAME/api/now/table/incident'
      snowUsername: '$SNOW_IM_USER'
      snowPassword: '$SNOW_IM_PASSWORD'
      snowConfigurationTemplate:
        #### these are set when we want to use specific values for impact/urgency/priority
        #        - field: '_impact_numeric_value'
        #          value: '1'
        #
        #        - field: '_urgency_numeric_value'
        #          value: '1'
        #
        #        - field: '_priority_numeric_value'
        #          value: '1'
        ########

        #### these are set when we want to use impact/urgency from the alert rule name
        - field: '_alert_rule_fields'
          value: [ 'impact', 'urgency' ]

        - field: '_alert_rulename_regex'
          value: '\[(\w+)\]\[(\w+)\]'

        - field: '_default_impact_value_high'
          value: '1'

        - field: '_default_impact_value_medium'
          value: '2'

        - field: '_default_impact_value_low'
          value: '3'

        - field: '_default_urgency_value_high'
          value: '1'

        - field: '_default_urgency_value_medium'
          value: '2'

        - field: '_default_urgency_value_low'
          value: '3'

        - field: '_default_priority_value_high'
          value: '1'

        - field: '_default_priority_value_medium'
          value: '2'

        - field: '_default_priority_value_low'
          value: '3'
        ########

        #### General options
        #        - field: '_alert_rule_name_routing_ids'
        #          value: [ ':SNI' ]

        - field: '_populate_work_notes'
          value: true

        - field: '_autoclose_ticket_on_clear'
          value: true

        - field: '_state_on_ticket_closed'
          value: 'Resolved'

        - field: '_state_on_alert_trigger'
          value: 'New'

        - field: '_state_on_alert_clear'
          value: 'Cleared'

        - field: '_default_agent_alert_assignment_group'
          value: 'Default Agent Alert Assignment Group'

        - field: '_default_test_alert_assignment_group'
          value: 'Default Test Alert Assignment Group'

        - field: '_use_generic_ci'
          value: true

        - field: '_generic_ci_value'
          value: 'ThousandEyes'

        - field: '_default_agent_ci'
          value: '__agentname'

        - field: '_default_test_ci'
          value: '__testname'
          ########

          #### Direct field mappings
        - field: 'caller_id'
          value: 'ThousandEyes SA'

        - field: 'category'
          value: 'Monitoring'

        - field: 'subcategory'
          value: 'Alert'

        - field: 'business_service'
          value: 'Business Service'

        - field: 'contact_type'
          value: 'Monitoring System'

        - field: 'work_notes'
          value: 'Created by ThousandEyes automation'
          phase: 'New'

        - field: 'close_notes'
          value: 'Service restored by ThousandEyes automation'
          phase: 'Resolved'

        - field: 'short_description'
          value: '__entityname is experiencing an issue. Please investigate.'

        - field: 'close_code'
          value: 'Closed/Resolved by Caller'
          phase: 'Resolved'
          ########
EOF
)
    SERVICES_SECTION=${SERVICES_SECTION}${SNOW_IM_SECTION}
}

function build_dynatrace_config_section () {
    echo ""
    echo "Building Dynatrace configuration..."
    echo ""

    user_input_loop "Enter the Dynatrace URL: " "WORD"
    DYNATRACE_URL=$ANSWER
    user_input_loop "Enter the Dynatrace token: " "WORD"
    DYNATRACE_TOKEN=$ANSWER
    user_input_loop "Enter the source for Dynatrace incidents (e.g. ThousandEyes): " "WORD"
    DYNATRACE_SOURCE=$ANSWER

    DYNATRACE_SECTION=$(cat << EOF

    - name: dynatrace
      dynatraceUrl: $DYNATRACE_URL
      dynatraceToken: $DYNATRACE_TOKEN
      dynatraceSource: $DYNATRACE_SOURCE
EOF
)
    SERVICES_SECTION=${SERVICES_SECTION}${DYNATRACE_SECTION}

}

function create_application_config_file(){
    create_server_yaml_stanza
    create_logging_yaml_stanza

    RUN_API_POLLER="y"

    echo "--------------------"
    echo "Configuration"
    echo "--------------------"
    echo "The following questions will help build the configuration for the Alert Integration Service. If unsure of something, use the default values."
    echo "The configuration will be held in $WORKING_DIR/config/application.yaml - you may modify this by hand if needed."
    echo ""

    SPLUNK_SET="n"
    SNMP_SET="n"
    SNOW_IM_SET="n"
    SNOW_EM_SET="n"
    DYNATRACE_SET="n"

    while true ; do
        k=0
        echo "Select an endpoint for which a configuration will be built. Currently supported: "

        for i in ${AIS_SUPPORTED_ENDPOINTS[@]} ; do
            k=$((k+1))
            echo "${k}. ${i}"
        done
        echo
        echo "0. Finished (or skip this section)"
        user_input_loop "Enter number: " "NUMBER"

        WEBHOOK_SERVER_ENDPOINTS=$(echo $ANSWER | tr "," " ")

        # build the endpoints stanza string
        create_endpoint_yaml_stanza

        if [ $ANSWER = 0 ]
        then
            break
        fi

        for endpoint in $WEBHOOK_SERVER_ENDPOINTS ; do
            case $endpoint in
            1)
                if [ ${SPLUNK_SET} = "n" ]
                then
                    build_splunk_config_section
                    SPLUNK_SET="y"
                else
                    echo "Splunk endpoint already configured."
                fi
            ;;

            2)
                if [ ${SNMP_SET} = "n" ]
                then
                    build_snmp_config_section
                    SNMP_SET="y"
                else
                    echo "SNMP endpoint already configured."
                fi
            ;;

            3)
                if [ ${SNOW_IM_SET} = "n" ]
                then
                    build_snow_im_config_section
                    SNOW_IM_SET="y"
                else
                    echo "ServiceNow (Incident Managment) endpoint already configured."
                fi
            ;;

            4)
                if [ ${SNOW_EM_SET} = "n" ]
                then
                    build_snow_em_config_section
                    SNOW_EM_SET="y"
                else
                    echo "ServiceNow (Event Management) endpoint already configured."
                fi
            ;;

            5)
                if [ ${DYNATRACE_SET} = "n" ]
                then
                    build_dynatrace_config_section
                    DYNATRACE_SET="y"
                else
                    echo "Dynatrace endpoint already configured."
                fi
            ;;

            *)
                echo "Unknown/unsupported endpoint."
            ;;

            esac
        done
    done

    append_to_config "$SERVER_STANZA"
    append_to_config "$LOGGING_STANZA"
    append_to_config "$ENDPOINTS_STANZA"
    append_to_config "$SERVICES_SECTION"

    echo

    user_input_loop "Should the API Poller be used to fetch data (alerts, metadata, etc) from the ThousandEyes API? [default:Y] " "LETTER"
    RUN_API_POLLER=$ANSWER

    echo

    if [ "$RUN_API_POLLER" = "y" ]
    then
        API_POLLER_RUN_APP="true"
        echo "---------------------------"
        echo "General API Poller settings"
        echo "---------------------------"
        read -p "Please provide the Organization name within ThousandEyes: " API_POLLER_ORGANIZATION_NAME
        read -p "Please provide the email address of the user that will be calling the API (e.g. user@example.com): " API_POLLER_EMAIL
        read -p "Please provide the basic authentication token for the user (see ThousandEyes UI under Account Settings -> Users and Roles): " API_POLLER_BASIC_AUTH_TOKEN
        read -p "Please provide the Account Group(s) to be monitored (separate by commas if multiple Account Groups, wildcards are supported, e.g. account-group-*): " API_POLLER_ACCOUNT_GROUPS
        echo ""

        echo "-------"
        echo "Options"
        echo "-------"
        user_input_loop "Retrieve test alerts from API? [Y/N] " "LETTER"
        API_POLLER_FETCH_TEST_ALERTS=$ANSWER
        user_input_loop "Retrieve Enterprise Agent alerts from API? [Y/N] " "LETTER"
        API_POLLER_FETCH_EA_ALERTS=$ANSWER

        if [ "$SPLUNK_SET" = "y" ]
        then
            user_input_loop "Retrieve test metric data from API and send to Splunk? [default:Y/N] " "LETTER"
            API_POLLER_FETCH_TEST_METRIC_DATA=$ANSWER
        fi

        create_api_poller_general_yaml_stanza
        append_to_config "$API_POLLER_GENERAL_STANZA"

        if [ "$API_POLLER_FETCH_TEST_ALERTS" = "y" ]
        then
            create_api_poller_alert_monitor_section
            append_to_config "$ALERT_MONITOR_STANZA"
        fi

        if [ "$API_POLLER_FETCH_EA_ALERTS" = "y" ]
        then
            create_api_poller_ea_monitor_section
            append_to_config "$EA_MONITOR_STANZA"
        fi

        if [ "$API_POLLER_FETCH_TEST_METRIC_DATA" = "y" ]
        then
            create_api_poller_test_metric_data_section
            append_to_config "$TEST_METRIC_DATA_STANZA"
        fi

        user_input_loop "Do we need to use a proxy to reach https://api.thousandeyes.com? [default:N] " "LETTER"
        API_POLLER_USE_PROXY=$ANSWER

        if [ "$API_POLLER_USE_PROXY" = "y" ]
        then
            read -p "Enter the IP address/hostname of the proxy: " API_POLLER_PROXY_IP_HOST
            read -p "Enter the port for the proxy: " API_POLLER_PROXY_PORT
            user_input_loop "Does the proxy require authentication? [Y/N] " "LETTER"
            API_POLLER_PROXY_REQUIRES_AUTHENTICATION=$ANSWER
            if [ "$API_POLLER_PROXY_REQUIRES_AUTHENTICATION" = "y" ]
            then
                read -p "Enter the username for the proxy: " API_POLLER_PROXY_USERNAME
                read -p "Enter the password for the proxy user: " API_POLLER_PROXY_PASSWORD

            fi
            create_api_poller_proxy_section
            append_to_config "$PROXY_STANZA"

            if [ "$API_POLLER_PROXY_REQUIRES_AUTHENTICATION" = "y" ]
            then
                create_api_poller_proxy_creds_section
                append_to_config "$PROXY_CREDS_SECTION"
            fi
        fi
    fi
    echo "$APPLICATION_YAML_TEXT" > $WORKING_DIR/config/application.yaml

}

function append_to_config () {
    TEXT_TO_APPEND=$1
    APPLICATION_YAML_TEXT="${APPLICATION_YAML_TEXT}${TEXT_TO_APPEND}"
}

function user_input_loop_with_choices () {
    QUESTION=$1
    CHOICES=$2

    read -p "$QUESTION" ANSWER
    ANSWER_IS_VALID=false
    while [ $ANSWER_IS_VALID = false ]
    do
        echo "ANSWR: $ANSWER"
        echo "choices: ${CHOICES[*]}"
        # if [[ " ${CHOICES[*]}" =~ "${ANSWER}" ]]
        if [ $(contains "${CHOICES[@]}" $ANSWER) == "y" ]; then
            ANSWER_IS_VALID=true
        else
            read -p "Enter choice: " ANSWER
        fi
    done

}


function user_input_loop () {
    QUESTION=$1
    RESPONSE_TYPE=$2

    read -p "$QUESTION" ANSWER

    INPUT_RECEIVED=false
    while [ $INPUT_RECEIVED = false ]
    do
        if [ "$RESPONSE_TYPE" = "LETTER" ]
        then
            if [ "$ANSWER" = "Y" ] || [ "$ANSWER" = "y" ]
            then
                ANSWER="y"
                INPUT_RECEIVED=true
            elif [ "$ANSWER" = "N" ] || [ "$ANSWER" = "n" ]
            then
                ANSWER="n"
                INPUT_RECEIVED=true
            else
                read -p "Enter yes or no [y/n]: " ANSWER
            fi
        elif [ "$RESPONSE_TYPE" = "NUMBER" ]
        then
            if [ ! -n "$ANSWER" ]
            then
                read -p "Enter numeric value: " ANSWER
            else
                INPUT_RECEIVED=true
            fi
        else
            if [ ! -n "$ANSWER" ]
            then
                read -p "Enter value: " ANSWER
            else
                INPUT_RECEIVED=true
            fi
        fi
    done
}

function usage () {
    echo "install.sh <Action>"
    echo
    echo "Available actions:"
    echo "-configure         : Build and create configuration"
}

# START EXECUTING HERE
echo
echo "---------------------------------------------"
echo "Alert Integration Service - Installation Tool"
echo "---------------------------------------------"

if [ "$1" = "-h" ]
then
    echo "Usage: "
    usage
    exit
fi

if [ -z ${ACTION} ]
then
    echo ""
    echo "Error: Please specify an action to take. Usage: "
    usage
    exit
fi

if [ "$ACTION" = "-configure" ]
then
    if [ $USER != "root" ]
    then
        read -p "Enter the path in which the application will run (user must have read/write permissions here): " WORKING_DIR
    else
        read -p "Enter the path in which the application will run: " WORKING_DIR
    fi

    echo

    if [ "${WORKING_DIR:0:1}" = '.' ] || [ "${WORKING_DIR:0:1}" != '/' ]
    then
        WORKING_DIR=$PWD/${WORKING_DIR#./}
    fi

    if [ -z "${JAVA}" ]
    then
        echo "Missing java - please install java and try again."
        exit
    fi

    echo "--------------------"
    echo "Installation Summary"
    echo "--------------------"
    echo "Working directory that the application will run in: $WORKING_DIR"
    echo "Java executable location: $JAVA"
    echo "Shell executable location: $BASH"

    echo ""
    read -p "Proceed with configuration and installation? [y/n] " CHOICE

    if [ "$CHOICE" = "y" ] || [ "$CHOICE" = "Y" ]
    then
        echo ""
        echo "Starting install."
        create_target_directory
        #fetch_build
        create_service_definition_file
        create_application_config_file
    else
        echo ""
        echo "Aborting installation."
        exit
    fi

    echo
    echo "Installation complete! The file ${WORKING_DIR}/alert-integration-service.service may be installed via systemctl, which will be responsible for operating the application."
fi
