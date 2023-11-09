import json

from alerta.models.alert import Alert
from alerta.webhooks import WebhookBase
from dateutil.parser import parse as parse_date
import re

from activityLog import ActivityLog


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
                resource=aLog.activityLog.authorization.scope.split("/")[-1]
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

                create_time=aLog.submissionTimestamp

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
            if payload['schemaId'] == 'AzureMonitorMetricAlert':
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
            else:
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
