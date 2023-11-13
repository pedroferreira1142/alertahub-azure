import json

from alerta.models.alert import Alert
from alerta.webhooks import WebhookBase
from dateutil.parser import parse as parse_date
import re
from datetime import datetime


SEVERITY_MAP = {
    '0': 'critical',       # Critical
    '1': 'major',          # Error
    '2': 'warning',        # Warning
    '3': 'informational',  # Informational
    '4': 'debug'           # Verbose
}

SEVERITY_MAP_COMMON = {
    'Sev0': 'critical',       # Critical
    'Sev1': 'major',          # Error
    'Sev2': 'warning',        # Warning
    'Sev3': 'informational',  # Informational
    'Sev4': 'debug'           # Verbose
}

SEVERITY_MAP_ACTIVITY_LOG = {
    'Critical': 'critical',       # Critical
    'Error': 'error',          # Error
    'Warning': 'warning',        # Warning
    'Informational': 'informational',  # Informational
}

DEFAULT_SEVERITY_LEVEL = '3'  # 'warning'
DEFAULT_SEVERITY_LEVEL_COMMON = 'Sev2'  # 'warning'
DEFAULT_SEVERITY_LEVEL_ACTIVITY_LOG = 'Warning'  # 'warning'


class AzureMonitorWebhook(WebhookBase):
    """
    Microsoft Azure Monitor alerts webhook
    https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-webhooks
    """

    def incoming(self, query_string, payload):
        attributes = {}
        tags = []
        value = []
        event_type = ""
        if 'data' in payload:
            if payload['schemaId'] == 'azureMonitorCommonAlertSchema':
                context = payload['data']['alertContext']
                environment = query_string.get('environment', 'Production')
                event = payload['data']['essentials']['monitoringService'] if payload['data']['essentials']['alertRule'] is None else payload['data']['essentials']['alertRule']
                
                if (hasattr(context, 'condition') and getattr(context, 'condition') is not None):
                    value = '{} {}'.format(context['condition']['allOf'][0]['metricValue'], context['condition']['allOf'][0]['metricName'])
                elif ('properties' in context):
                    value = [] if context['properties'] is None else ['{}={}'.format(k, v) for k, v in context['properties'].items()]

                group = payload['data']['essentials']['signalType']
                service = [payload['data']['essentials']['monitoringService']]
                if 'configurationItems' in payload['data']['essentials'] and len(payload['data']['essentials']['configurationItems']) > 0:
                    resource = payload['data']['essentials']['configurationItems'][0]
                elif ('configurationItems' in payload['data']['essentials'] and len(payload['data']['essentials']['configurationItems']) == 0):
                    resource = payload['data']['essentials']['alertTargetIDs'][0].split("/")[-1]
                elif ('properties' in context and 'service' in context['properties']):
                    resource = context['properties']['service']

                event_type = payload['data']['essentials']['signalType']

                if 'properties' in context and context['properties'] is not None:
                    properties_keys = context['properties'].keys()
                    for key in properties_keys:
                        attributes[key] = context['properties'][key]

                pattern = r'/subscriptions/[0-9a-fA-F-]+'
                attributes.update({
                    "subscriptionId": re.sub(pattern, '', payload['data']['essentials']['alertTargetIDs'][0]) 
                        if payload['data']['essentials']['alertTargetIDs'] and len(payload['data']['essentials']['alertTargetIDs']) >= 0 
                        else ""
                })
                create_time = parse_date(payload['data']['essentials']['firedDateTime'])
                
                if (hasattr(payload['data'], 'customProperties') and getattr(payload['data'], 'customProperties') is not None):
                    tags = [] if payload['data']['customProperties'] is None else ['{}={}'.format(k, v) for k, v in payload['data']['customProperties'].items()]
                elif ('properties' in context):
                    tags = [] if context['properties'] is None else ['{}={}'.format(k, v) for k, v in context['properties'].items()]
                

                if payload['data']['essentials']['monitorCondition'] == 'Resolved' or payload['data']['essentials']['monitorCondition'] == 'Deactivated':
                    severity = 'ok'
                else:
                    severity = SEVERITY_MAP_COMMON[context.get('severity', DEFAULT_SEVERITY_LEVEL_COMMON)]

                if (hasattr(context, 'condition') and getattr(context, 'condition') is not None):
                    text = '{}: {} {} ({} {})'.format(
                        severity.upper(),
                        context['condition']['allOf'][0]['metricValue'],
                        context['condition']['allOf'][0]['metricName'],
                        context['condition']['allOf'][0]['operator'],
                        context['condition']['allOf'][0]['threshold'])
                else:
                    text = payload['data']['essentials']['description']

            # ================================ Microsoft.Insights/activityLogs
            elif payload['schemaId'] == 'Microsoft.Insights/activityLogs':
                environment='Production'
                event_type = "Activity Logs"
                aLog = ActivityLog(payload)

                attributes = aLog.extractAttributes()
                resource=aLog.activityLog.resourceId.split("/")[-1] if not hasattr(aLog.activityLog, 'authorization') else aLog.activityLog.authorization.scope.split("/")[-1]
                event=aLog.activityLog.operationName

                if aLog.status == 'Resolved' or aLog.status == 'Deactivated':
                    severity = 'ok'
                else:
                    severity = SEVERITY_MAP_ACTIVITY_LOG[aLog.activityLog.level]

                service=[aLog.resourceType]
                group=aLog.resourceGroupName
                value=aLog.status
                text=aLog.activityLog.description
                tags=[]

                create_time=aLog.activityLog.eventTimestamp

            # ================================ Availibilty Alert
            elif payload['schemaId'] == 'AzureMonitorMetricAlert' and "data" in payload and "data" in payload['data'] and "availability" in payload['data']['data']['context']['id']:
                environment='Production'
                event_type = "Availibilty Alert"
                aAlert = AvailibiltyAlert(payload)
            
                if aAlert.status == 'Resolved' or aAlert.status == 'Deactivated':
                    severity = 'ok'
                else:
                    severity = SEVERITY_MAP[aAlert.severity]

                resource=aAlert.resourceName
                event=aAlert.resourceType
                attributes = aAlert.extractAttributes()
                service = [aAlert.resourceType]
                group=aAlert.resourceGroupName
                tags= []
                text = '{}: {} {} ({} {})'.format(
                    severity.upper(),
                    aAlert.allOf[0]['metricValue'],
                    aAlert.allOf[0]['metricName'],
                    aAlert.allOf[0]['operator'],
                    aAlert.allOf[0]['threshold'])
                value = '{} {}'.format(
                    aAlert.allOf[0]['metricValue'],
                    aAlert.allOf[0]['metricName'])
                create_time=aAlert.createTime

            # ================================ CostBudgetAlert
            elif payload['schemaId'] == 'AIP Budget Notification':
                environment='Production'
                event_type = "Cost Budget Alert"
                cAlert = CostBudgetAlert(payload)

                severity = SEVERITY_MAP['3']
                resource=cAlert.budgetName
                event=cAlert.schemaId
                attributes = cAlert.extractAttributes()
                service = [cAlert.subscriptionName]
                group=cAlert.resourceGroup
                tags= []
                text = '{}: {} {} ({} {})'.format(
                    severity.upper(),
                    cAlert.budgetName,
                    cAlert.budgetType,
                    cAlert.notificationThresholdAmount,
                    cAlert.budget)
                value = cAlert.spendingAmount
                create_time=cAlert.budgetStartDate

            # ================================ LogAlertV2
            elif payload['schemaId'] == 'Microsoft.Insights/LogAlert' and 'data' in payload and 'data' in payload['data'] and 'essentials' in payload['data']['data']:
                lAlertV2 = LogAlertV2(payload)

                environment='Production'
                event_type = "Log Alert"

                if lAlertV2.monitorCondition == 'Resolved' or lAlertV2.monitorCondition == 'Deactivated':
                    severity = 'ok'
                else:
                    severity = SEVERITY_MAP_COMMON[lAlertV2.severity]

                resource= lAlertV2.extractResourceName()
                event=lAlertV2.alertRule
                attributes = lAlertV2.extractSubscriptionId()
                service = [lAlertV2.monitoringService]
                group=lAlertV2.signalType
                tags= []
                text = lAlertV2.description
                value = lAlertV2.description
                create_time=lAlertV2.firedDateTime

            # ================================ LogAlertV1
            elif payload['schemaId'] == 'Microsoft.Insights/LogAlert':
                lAlert = LogAlertV1(payload)
                resourceGroup, resourceName = lAlert.extractValues()

                environment='Production'
                event_type = "Log Alert"

                if lAlert.severity in SEVERITY_MAP:
                    severity = SEVERITY_MAP[lAlert.severity]
                else:
                    severity = SEVERITY_MAP_COMMON[lAlert.severity]  

                resource=resourceName
                event=lAlert.schemaId
                attributes = lAlert.extractAttributes()
                service = [lAlert.alertType]
                group=resourceGroup
                tags= []
                text = '{}: {} {} {} ({})'.format(
                    severity.upper(),
                    lAlert.alertRuleName,
                    lAlert.alertType,
                    lAlert.searchQuery,
                    lAlert.description)
                value = lAlert.searchQuery
                create_time=lAlert.searchIntervalStartTimeUtc

            else:
                context = payload['data']['context']

                status = payload['data']['status']
                if status == 'Resolved' or status == 'Deactivated':
                    severity = 'ok'
                else:
                    severity = SEVERITY_MAP[context.get('severity', DEFAULT_SEVERITY_LEVEL)]

                resource = context['resourceName']
                event = context['name']
                environment = query_string.get('environment', 'Production')
                service = [context['resourceType']]
                group = context['resourceGroupName']
                tags = [] if payload['data']['properties'] is None else ['{}={}'.format(k, v) for k, v in
                                                                        payload['data']['properties'].items()]
                create_time = parse_date(context['timestamp'])

            # ======================================= AzureMonitorMetricAlert
            if payload['schemaId'] == 'AzureMonitorMetricAlert'and event_type != "Availibilty Alert":
                event_type = 'MetricAlert'
                text = '{}: {} {} ({} {})'.format(
                    severity.upper(),
                    context['condition']['allOf'][0]['metricValue'],
                    context['condition']['allOf'][0]['metricName'],
                    context['condition']['allOf'][0]['operator'],
                    context['condition']['allOf'][0]['threshold'])
                value = '{} {}'.format(
                    context['condition']['allOf'][0]['metricValue'],
                    context['condition']['allOf'][0]['metricName'])
            elif event_type != "Log Alert" and event_type != "Availibilty Alert" and event_type != "Activity Logs":
                text = '{}'.format(severity.upper())
                value = ''
                event_type = 'EventAlert'

        else:
            context = payload['context']

            resource = context['resourceName']
            event = context['name']
            environment = query_string.get('environment', 'Production')

            if payload['status'] == 'Activated':
                severity = 'critical'
            elif payload['status'] == 'Resolved':
                severity = 'ok'
            else:
                severity = 'indeterminate'

            service = [context['resourceType']]
            group = context['resourceGroupName']

            if context['conditionType'] == 'Metric':
                condition = context['condition']
                text = '{}: {} {} ({} {})'.format(
                    severity.upper(),
                    condition['metricValue'],
                    condition['metricName'],
                    condition['operator'],
                    condition['threshold']
                )
                value = '{} {}'.format(
                    condition['metricValue'],
                    condition['metricName']
                )
            else:
                text = '{}'.format(severity.upper())
                value = ''

            tags = [] if payload['properties'] is None else ['{}={}'.format(k, v) for k, v in
                                                             payload['properties'].items()]
            event_type = '{}Alert'.format(context['conditionType'])
            create_time = parse_date(context['timestamp'])
        alert = Alert(
            resource=resource,
            event=event,
            environment=environment,
            severity=severity,
            service=service,
            group=group,
            value=value,
            text=text,
            tags=tags,
            attributes = attributes,
            origin='Azure Monitor',
            type=event_type,
            create_time=create_time,
            raw_data=json.dumps(payload)
        )

        return alert



class ActivityLog:
    class Authorization:
        def __init__(self, authorization_data):
            self.action = authorization_data.get("action")
            self.scope = authorization_data.get("scope")

    class Properties:
        def __init__(self, properties_data):
            self.eventCategory = properties_data.get("eventCategory")
            self.entity = properties_data.get("entity")
            self.message = properties_data.get("message")
            self.hierarchy = properties_data.get("hierarchy")

    class ActivityLogDetails:
        def __init__(self, activity_log_data):
            if ("authorization" in activity_log_data):
                self.authorization = ActivityLog.Authorization(activity_log_data.get("authorization", None))
            self.channels = activity_log_data.get("channels")
            self.claims = activity_log_data.get("claims")
            self.caller = activity_log_data.get("caller")
            self.correlationId = activity_log_data.get("correlationId")
            self.description = activity_log_data.get("description")
            self.eventSource = activity_log_data.get("eventSource")
            self.eventTimestamp = parse_date(activity_log_data.get("eventTimestamp"))
            self.eventDataId = activity_log_data.get("eventDataId")
            self.level = activity_log_data.get("level")
            self.operationName = activity_log_data.get("operationName")
            self.operationId = activity_log_data.get("operationId")
            self.properties = activity_log_data.get("properties", {})
            if ("submissionTimestamp" in activity_log_data):
                self.submissionTimestamp = parse_date(activity_log_data.get("submissionTimestamp"))
            self.subscriptionId = activity_log_data.get("subscriptionId")
            self.resourceId = activity_log_data.get("resourceId")

        

    def __init__(self, data):
        self.schemaId = data.get("schemaId")
        self.status = data.get("data", {}).get("status")
        context_data = data.get("data", {}).get("context", {})

        self.activityLog = ActivityLog.ActivityLogDetails(context_data.get("activityLog", {}))
        self.resourceGroupName = context_data.get("resourceGroupName")
        self.resourceProviderName = context_data.get("resourceProviderName")
        self.status = context_data.get("status")
        self.subStatus = context_data.get("subStatus")
        self.resourceType = context_data.get("resourceType")
        self.properties = data.get("data", {}).get("properties")

    def extractAttributes(self):
        attributes = {}

        if self.properties is not None:
            properties_keys = self.properties.keys()
            for key in properties_keys:
                attributes[key] = self.properties[key]

        if self.activityLog.properties is not None:
            properties_keys = self.activityLog.properties.keys()
            for key in properties_keys:
                attributes[key] = self.activityLog.properties[key]

        if self.activityLog.subscriptionId:
            attributes.update({"subscriptionId": self.activityLog.subscriptionId})

        return attributes
    


class AvailibiltyAlert:
    def __init__(self, payload):
        self.schema_id = payload.get("schemaId")
        self.data = payload.get("data", {}).get("data", {})
        self.version = self.data.get("version")
        self.properties = self.data.get("properties", {})
        self.status = self.data.get("status")
        self.context = self.data.get("context", {})
        
        # Context attributes
        self.alertId = self.context.get("id")
        self.alertName = self.context.get("name")
        self.description = self.context.get("description")
        self.condition_type = self.context.get("conditionType")
        self.severity = self.context.get("severity")
        self.condition = self.context.get("condition", {})
        
        # Condition attributes
        self.windowSize = self.condition.get("windowSize")
        self.allOf = self.condition.get("allOf", [])
        
        # Additional context attributes
        self.subscriptionId = self.context.get("subscriptionId")
        self.resourceGroupName = self.context.get("resourceGroupName")
        self.resourceName = self.context.get("resourceName")
        self.resourceType = self.context.get("resourceType")
        self.resourceId = self.context.get("resourceId")
        self.portalLink = self.context.get("portalLink")
        self.createTime = datetime.now()

    def extractAttributes(self):
        attributes = {}

        if self.properties is not None:
            properties_keys = self.properties.keys()
            for key in properties_keys:
                attributes[key] = self.properties[key]

        if self.subscriptionId:
            attributes.update({"subscriptionId": self.subscriptionId})

        return attributes
    

class CostBudgetAlert:
    def __init__(self, payload):
        self.schemaId = payload.get("schemaId")
        self.data = payload.get("data", {})
        self.subscriptionName = self.data.get("SubscriptionName")
        self.subscriptionId = self.data.get("SubscriptionId")
        self.enrollmentNumber = self.data.get("EnrollmentNumber")
        self.departmentName = self.data.get("DepartmentName")
        self.accountName = self.data.get("AccountName")
        self.billingAccountId = self.data.get("BillingAccountId")
        self.billingProfileId = self.data.get("BillingProfileId")
        self.invoiceSectionId = self.data.get("InvoiceSectionId")
        self.resourceGroup = self.data.get("ResourceGroup")
        self.spendingAmount = float(self.data.get("SpendingAmount", 0.0))
        self.budgetStartDate = self.parse_date(self.data.get("BudgetStartDate"))
        self.budget = float(self.data.get("Budget", 0.0))
        self.unit = self.data.get("Unit")
        self.budgetCreator = self.data.get("BudgetCreator")
        self.budgetName = self.data.get("BudgetName")
        self.budgetType = self.data.get("BudgetType")
        self.notificationThresholdAmount = float(self.data.get("NotificationThresholdAmount", 0.0))

    def parse_date(self, date_str):
        if date_str:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        return None
    
    def extractAttributes(self):
        attributes = {}

        if self.subscriptionId:
            attributes.update({"subscriptionId": self.subscriptionId})

        return attributes
class LogAlertV1:
    def __init__(self, payload):
        data = payload.get('data')
        self.schemaId = data.get("schemaId", "Microsoft.Insights/LogAlert")
        self.subscriptionId = data.get("SubscriptionId")
        self.alertRuleName = data.get("AlertRuleName", "")
        self.searchQuery = data.get("SearchQuery", "")
        self.searchIntervalStartTimeUtc = self.parse_date(data.get("SearchIntervalStartTimeUtc", ""))
        self.searchIntervalEndtimeUtc = self.parse_date(data.get("SearchIntervalEndtimeUtc", ""))
        self.alertThresholdOperator = data.get("AlertThresholdOperator", "")
        self.alertThresholdValue = data.get("AlertThresholdValue", 0)
        self.resultCount = data.get("ResultCount", 0)
        self.searchIntervalInSeconds = data.get("SearchIntervalInSeconds", 0)
        self.linkToSearchResults = data.get("LinkToSearchResults", "")
        self.linkToFilteredSearchResultsUI = data.get("LinkToFilteredSearchResultsUI", "")
        self.linkToSearchResultsAPI = data.get("LinkToSearchResultsAPI", "")
        self.linkToFilteredSearchResultsAPI = data.get("LinkToFilteredSearchResultsAPI", "")
        self.description = data.get("Description", "")
        self.severity = data.get("Severity", "")
        self.searchResult = self.parse_search_result(data.get("SearchResult", {}))
        self.workspaceId = data.get("WorkspaceId", "")
        self.resourceId = data.get("ResourceId", "")
        self.alertType = data.get("AlertType", "")
        self.dimensions = data.get("Dimensions", [])

    def parse_search_result(self, search_result):
        tables = []
        for table in search_result.get("tables", []):
            columns = [{"name": col["name"], "type": col["type"]} for col in table.get("columns", [])]
            rows = [[row for row in table_row] for table_row in table.get("rows", [])]
            tables.append({"name": table.get("name", ""), "columns": columns, "rows": rows})

        data_sources = []
        for data_source in search_result.get("dataSources", []):
            tables = data_source.get("tables", [])

            data_sources.append({
                "resourceId": data_source.get("resourceId", ""),
                "region": data_source.get("region", ""),
                "tables": tables
            })

        return {"tables": tables, "dataSources": data_sources}
    
    def extractAttributes(self):
        attributes = {}
        print("======================================")
        print(self.subscriptionId)
        if self.subscriptionId:
            attributes.update({"subscriptionId": self.subscriptionId})
        return attributes

    def extractValues(self):

        if self.resourceId is not None:
            # Extract value after "resourceGroups"
            match_rg = re.search(r'/resourceGroups/([^/]+)', self.resourceId)
            resourceGroup = match_rg.group(1) if match_rg else None

            # Extract last substring after "/"
            resourceName = self.resourceId.split('/')[-1]

            return resourceGroup, resourceName
        
    def parse_date(self, date_str):
        if date_str:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        return None
    
class LogAlertV2:
    def __init__(self, data):
        payload = data.get('data', {})
        self.schemaId = payload.get('schemaId', "Microsoft.Insights/LogAlert")
        self.alertId = payload.get('data', {}).get('essentials', {}).get('alertId')
        self.alertRule = payload.get('data', {}).get('essentials', {}).get('alertRule')
        self.severity = payload.get('data', {}).get('essentials', {}).get('severity')
        self.signalType = payload.get('data', {}).get('essentials', {}).get('signalType')
        self.monitorCondition = payload.get('data', {}).get('essentials', {}).get('monitorCondition')
        self.monitoringService = payload.get('data', {}).get('essentials', {}).get('monitoringService')
        self.alertTargetIDs = payload.get('data', {}).get('essentials', {}).get('alertTargetIDs', [])
        self.configurationItems = payload.get('data', {}).get('essentials', {}).get('configurationItems', [])
        self.originAlertId = payload.get('data', {}).get('essentials', {}).get('originAlertId')
        self.firedDateTime = self.parse_date(payload.get('data', {}).get('essentials', {}).get('firedDateTime'))
        self.description = payload.get('data', {}).get('essentials', {}).get('description')
        self.essentialsVersion = payload.get('data', {}).get('essentials', {}).get('essentialsVersion')
        self.alertContextVersion = payload.get('data', {}).get('essentials', {}).get('alertContextVersion')

        self.customProperties = payload.get('data', {}).get('alertContext', {}).get('properties', {})
        self.conditionType = payload.get('data', {}).get('alertContext', {}).get('conditionType')
        self.windowSize = payload.get('data', {}).get('alertContext', {}).get('condition', {}).get('windowSize')
        self.allOfConditions = payload.get('data', {}).get('alertContext', {}).get('condition', {}).get('allOf', [])
        self.windowStartTime = payload.get('data', {}).get('alertContext', {}).get('condition', {}).get('windowStartTime')
        self.windowEndTime = payload.get('data', {}).get('alertContext', {}).get('condition', {}).get('windowEndTime')

    def extractResourceName(self):
        if (len(self.configurationItems) > 0):
            return self.configurationItems[0]
        elif (len(self.configurationItems)== 0):
            return self.alertTargetIDs[0].split("/")[-1]
        
    def extractSubscriptionId(self):
        attributes = {}
        pattern = r'/subscriptions/[0-9a-fA-F-]+'
        attributes.update({
            "subscriptionId": re.sub(pattern, '', self.alertTargetIDs[0]) 
                if self.alertTargetIDs and len(self.alertTargetIDs) >= 0 
                else ""
        })

        return attributes
    
    def extractValue(self):
        if (len(self.allOfConditions) > 0):
            return '{} {}'.format(self.allOfConditions[0]['metricValue'], self.allOfConditions[0]['metricName'])
        else:
            return self.description
        
    def parse_date(self, date_str):
        if date_str:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        return None