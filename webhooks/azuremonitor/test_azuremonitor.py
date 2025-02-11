import json
import unittest

import alerta_azuremonitor
from alerta.app import create_app, custom_webhooks


class AzureMonitoringWebhookTestCase(unittest.TestCase):

    def setUp(self):

        test_config = {
            'TESTING': True,
            'AUTH_REQUIRED': False
        }
        self.app = create_app(test_config)
        self.client = self.app.test_client()

        custom_webhooks.webhooks['azuremonitor'] = alerta_azuremonitor.AzureMonitorWebhook(
        )

    # def testServiceHealth(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId":"azureMonitorCommonAlertSchema",
    #         "data":{
    #             "essentials":{
    #                 "alertId":"/subscriptions/b6ccbd50-ed12-4c4f-b4bc-151fb377c570/providers/Microsoft.AlertsManagement/alerts/a69b1e9f-7b61-32f9-2c90-e0188a6d000d",
    #                 "alertRule":"UNIVERSO | VLL | OPERATION FAILURE 400",
    #                 "severity":"Sev1",
    #                 "signalType":"Log",
    #                 "monitorCondition":"Fired",
    #                 "monitoringService":"Log Alerts V2",
    #                 "alertTargetIDs":[
    #                     "/subscriptions/b6ccbd50-ed12-4c4f-b4bc-151fb377c570/resourcegroups/apim-prd/providers/microsoft.insights/components/ai-apim-prd"
    #                 ],
    #                 "configurationItems":[
    #                     "/subscriptions/b6ccbd50-ed12-4c4f-b4bc-151fb377c570/resourceGroups/APIM-PRD/providers/microsoft.insights/components/AI-APIM-PRD"
    #                 ],
    #                 "originAlertId":"53c911bc-900c-a5b4-8a33-886fbc52323c",
    #                 "firedDateTime":"2023-11-15T09:58:11.5525071Z",
    #                 "description":"",
    #                 "essentialsVersion":"1.0",
    #                 "alertContextVersion":"1.0"
    #             },
    #             "alertContext":{
    #                 "properties":{
                        
    #                 },
    #                 "conditionType":"LogQueryCriteria",
    #                 "condition":{
    #                     "windowSize":"PT1H",
    #                     "allOf":[
    #                         {
    #                             "searchQuery":"let deps=dependencies\n | where client_Type != \"Browser\"\n | where operation_Name contains \"uws-loyalty;\" or operation_Name contains \"smc-loyalty;\"\n | summarize TotalErros=count()\n by\n operation_Name,\n itemCount,\n success,\n duration,\n operation_Id,\n resultCode,\n target,\n name\n | project\n itemCount,\n success,\n operation=replace(\"(.*/)[0-9]+(.*)\", @\"\\1_\\2\", name),\n duration,\n operation_Id,\n resultCode,\n target;\ndeps\n| where success == false\n| lookup kind=leftouter (\n exceptions\n | project operation_Id, outerMessage, type\n )\n on operation_Id\n| join kind=inner (deps\n | summarize totalCount=sum(itemCount) by operation\n )\n on operation\n| summarize \n failed=sum(itemCount), total=max(totalCount)\n by\n operation,\n success,\n resultCode,\n type,\n outerMessage,\n target \n| project\n operation,\n target,\n failed,\n total,\n failRateP=100.0 * failed / total,\n resultCode\n| render timechart \n| where failRateP >= 10\n| where total != failed\n| where failed >= 10\n| where resultCode == 400\n\n",
    #                             "metricMeasureColumn":null,
    #                             "targetResourceTypes":"['microsoft.insights/components']",
    #                             "operator":"GreaterThanOrEqual",
    #                             "threshold":"1",
    #                             "timeAggregation":"Count",
    #                             "dimensions":[
    #                                 {
    #                                     "name":"failed",
    #                                     "value":"91"
    #                                 },
    #                                 {
    #                                     "name":"failRateP",
    #                                     "value":"91"
    #                                 },
    #                                 {
    #                                     "name":"operation",
    #                                     "value":"POST /v1/cards/_/permanentJoin"
    #                                 },
    #                                 {
    #                                     "name":"resultCode",
    #                                     "value":"400"
    #                                 },
    #                                 {
    #                                     "name":"total",
    #                                     "value":"100"
    #                                 }
    #                             ],
    #                             "metricValue":0.0,
    #                             "failingPeriods":{
    #                                 "numberOfEvaluationPeriods":1,
    #                                 "minFailingPeriodsToAlert":1
    #                             },
    #                             "linkToSearchResultsUI":"https://portal.azure.com#@d4de515c-b48a-4922-bdeb-e83ab400ce1c/blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/source/Alerts.EmailLinks/scope/%7B%22resources%22%3A%5B%7B%22resourceId%22%3A%22%2Fsubscriptions%2Fb6ccbd50-ed12-4c4f-b4bc-151fb377c570%2FresourceGroups%2FAPIM-PRD%2Fproviders%2Fmicrosoft.insights%2Fcomponents%2FAI-APIM-PRD%22%7D%5D%7D/q/eJytVE1P3DAQve%2BvmOaU0ADZqpcKuaqKeugBhCpugFauMwsGx47siZZF%2FfH4I8TJqhwq1YfIGr9573n8FIUELfaO%2BQ%2FqFrWQ6Fbg1x%2FYPaBFEEqips31vkf4wKD4bs3OoS0WINOj5SSN3lzyzvcYTVxqB8Wwc8fK7Lmi%2FVkBxr6PdJ3IyJHcDV3HrXxBuDbE1Q9rjWPCDJrKKkLC%2Br2ftkvyeqpLwu48tOWSG4RA53KhHVJr%2FRe2n22uWnSDonPTzviJ23uckWuvPl6ht%2BYRBf2TlUmYWewVF1gW5cnRaXXTHH%2B5%2B%2Bi3VVHDt%2BJ2vbn95HdBrfqfFzlbhUis3h539AeMwZYrh%2F5AGfM09PAkdcsUbskMhBagjET4LLAPcm45g6UPiD0XnpjfYw3k8xXh6WGNXqC95KOROglKrb1YGT0e5oRCTuJ8mS%2BW07QrH5PM%2BI7Qas4UT7dcKmwPqOqkwjr%2BXGa9RDeGcaJMo1288OHcw83r1DWfSDqL7wHe2DxHB%2Bzz9CXDYz14y%2BVfnPCKrZvmpIGjEQinc1R25gVt%2BB1YINmheOA2mkh5mMjgK4N1M9UjU%2FhHJO4F3kstwVkr5Opz07wC/prettify/1/timespan/2023-11-15T08%3a52%3a20.0000000Z%2f2023-11-15T09%3a52%3a20.0000000Z",
    #                             "linkToFilteredSearchResultsUI":"https://portal.azure.com#@d4de515c-b48a-4922-bdeb-e83ab400ce1c/blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/source/Alerts.EmailLinks/scope/%7B%22resources%22%3A%5B%7B%22resourceId%22%3A%22%2Fsubscriptions%2Fb6ccbd50-ed12-4c4f-b4bc-151fb377c570%2FresourceGroups%2FAPIM-PRD%2Fproviders%2Fmicrosoft.insights%2Fcomponents%2FAI-APIM-PRD%22%7D%5D%7D/q/eJytVMFu1DAUvOcrHrlsUrZNFnGpKqOKigNIQAV7o2hlnLdbt44d2Q7bRf147DjE64g9IJFDZD3Pmxk%2FjyzQQoOdIe6HskHJOJoM3PcM%2B3vUCExwlHazPnQILwjkb7XaG9R5AlIdamq5kptPtHU9SlrKpYG835tzoQ5U2MNVDkqfRpqWReRIbvq2pZr%2FQlgrS8U7rZUhTPXSFuUA8d%2BPw7RMyZdTnVtsb3xbLJmeMTQmFpo%2BtC7%2Fwva%2BiVWNphf2RjVH%2FJbqHR6RS6c%2BHqHT6gGZ%2FScrkzDR2AnKsMiLi7Oq%2FFafX35%2F6ZZlvoTr%2FG61uXvlVl6t%2FJ8Hucp8JLI%2Flzv6A0JgS4VBtyGUeuw7eOSyIQK3VvUWNUAxEOETw87LmXQGqQ8Yej46YrrDJViXrwEeLlbJBO0kHxSXQZBL6cSKweM8J9bnZJgvccVimnbpYhIZTwhlx0zD7pZygc2MahlUSEufiqgX6MYwTpRhtMkNz%2BfuTx5WyUSyeB%2BQpTmasR%2BnLxge695bLH%2BhFm%2FJqq4vajgbgVAdo6IzJ6j9c6DB8hbZPdWDiZCHiQzeEFjVU916Jv9GBO4E76RScNTyuXpd15HFWM3lrghtpd%2B%2BXlyuFkBlk%2B4OJk4BpiGNgNvPX9dQ%2FVxVjOrGVJvK7bdUurftg0vWrDm6G7udwRlkOO2464a6%2BA0%3D/prettify/1/timespan/2023-11-15T08%3a52%3a20.0000000Z%2f2023-11-15T09%3a52%3a20.0000000Z",
    #                             "linkToSearchResultsAPI":"https://api.applicationinsights.io/v1/apps/2240ec0b-63cf-415d-9b71-80e6c007466e/query?query=let%20deps%3Ddependencies%0A%20%20%20%20%7C%20where%20client_Type%20%21%3D%20%22Browser%22%0A%20%20%20%20%7C%20where%20operation_Name%20contains%20%22uws-loyalty%3B%22%20or%20operation_Name%20contains%20%22smc-loyalty%3B%22%0A%20%20%20%20%7C%20summarize%20TotalErros%3Dcount%28%29%0A%20%20%20%20%20%20%20%20by%0A%20%20%20%20%20%20%20%20operation_Name%2C%0A%20%20%20%20%20%20%20%20itemCount%2C%0A%20%20%20%20%20%20%20%20success%2C%0A%20%20%20%20%20%20%20%20duration%2C%0A%20%20%20%20%20%20%20%20operation_Id%2C%0A%20%20%20%20%20%20%20%20resultCode%2C%0A%20%20%20%20%20%20%20%20target%2C%0A%20%20%20%20%20%20%20%20name%0A%20%20%20%20%7C%20project%0A%20%20%20%20%20%20%20%20itemCount%2C%0A%20%20%20%20%20%20%20%20success%2C%0A%20%20%20%20%20%20%20%20operation%3Dreplace%28%22%28.%2A%2F%29%5B0-9%5D%2B%28.%2A%29%22%2C%20%40%22%5C1_%5C2%22%2C%20name%29%2C%0A%20%20%20%20%20%20%20%20duration%2C%0A%20%20%20%20%20%20%20%20operation_Id%2C%0A%20%20%20%20%20%20%20%20resultCode%2C%0A%20%20%20%20%20%20%20%20target%3B%0Adeps%0A%7C%20where%20success%20%3D%3D%20false%0A%7C%20lookup%20kind%3Dleftouter%20%20%28%0A%20%20%20%20exceptions%0A%20%20%20%20%7C%20project%20operation_Id%2C%20outerMessage%2C%20type%0A%20%20%20%20%29%0A%20%20%20%20on%20operation_Id%0A%7C%20join%20kind%3Dinner%20%28deps%0A%20%20%20%20%7C%20summarize%20totalCount%3Dsum%28itemCount%29%20by%20operation%0A%20%20%20%20%29%0A%20%20%20%20on%20operation%0A%7C%20summarize%20%0A%20%20%20%20failed%3Dsum%28itemCount%29%2C%20total%3Dmax%28totalCount%29%0A%20%20%20%20by%0A%20%20%20%20operation%2C%0A%20%20%20%20success%2C%0A%20%20%20%20resultCode%2C%0A%20%20%20%20type%2C%0A%20%20%20%20outerMessage%2C%0A%20%20%20%20target%20%0A%7C%20project%0A%20%20%20%20operation%2C%0A%20%20%20%20target%2C%0A%20%20%20%20failed%2C%0A%20%20%20%20total%2C%0A%20%20%20%20failRateP%3D100.0%20%2A%20failed%20%2F%20total%2C%0A%20%20%20%20resultCode%0A%7C%20render%20timechart%20%0A%7C%20where%20failRateP%20%3E%3D%2010%0A%7C%20where%20total%20%21%3D%20failed%0A%7C%20where%20failed%20%3E%3D%2010%0A%7C%20where%20resultCode%20%3D%3D%20400&timespan=2023-11-15T08%3a52%3a20.0000000Z%2f2023-11-15T09%3a52%3a20.0000000Z",
    #                             "linkToFilteredSearchResultsAPI":"https://api.applicationinsights.io/v1/apps/2240ec0b-63cf-415d-9b71-80e6c007466e/query?query=let%20deps%3Ddependencies%0A%20%20%20%20%7C%20where%20client_Type%20%21%3D%20%22Browser%22%0A%20%20%20%20%7C%20where%20operation_Name%20contains%20%22uws-loyalty%3B%22%20or%20operation_Name%20contains%20%22smc-loyalty%3B%22%0A%20%20%20%20%7C%20summarize%20TotalErros%3Dcount%28%29%0A%20%20%20%20%20%20%20%20by%0A%20%20%20%20%20%20%20%20operation_Name%2C%0A%20%20%20%20%20%20%20%20itemCount%2C%0A%20%20%20%20%20%20%20%20success%2C%0A%20%20%20%20%20%20%20%20duration%2C%0A%20%20%20%20%20%20%20%20operation_Id%2C%0A%20%20%20%20%20%20%20%20resultCode%2C%0A%20%20%20%20%20%20%20%20target%2C%0A%20%20%20%20%20%20%20%20name%0A%20%20%20%20%7C%20project%0A%20%20%20%20%20%20%20%20itemCount%2C%0A%20%20%20%20%20%20%20%20success%2C%0A%20%20%20%20%20%20%20%20operation%3Dreplace%28%22%28.%2A%2F%29%5B0-9%5D%2B%28.%2A%29%22%2C%20%40%22%5C1_%5C2%22%2C%20name%29%2C%0A%20%20%20%20%20%20%20%20duration%2C%0A%20%20%20%20%20%20%20%20operation_Id%2C%0A%20%20%20%20%20%20%20%20resultCode%2C%0A%20%20%20%20%20%20%20%20target%3B%0Adeps%0A%7C%20where%20success%20%3D%3D%20false%0A%7C%20lookup%20kind%3Dleftouter%20%20%28%0A%20%20%20%20exceptions%0A%20%20%20%20%7C%20project%20operation_Id%2C%20outerMessage%2C%20type%0A%20%20%20%20%29%0A%20%20%20%20on%20operation_Id%0A%7C%20join%20kind%3Dinner%20%28deps%0A%20%20%20%20%7C%20summarize%20totalCount%3Dsum%28itemCount%29%20by%20operation%0A%20%20%20%20%29%0A%20%20%20%20on%20operation%0A%7C%20summarize%20%0A%20%20%20%20failed%3Dsum%28itemCount%29%2C%20total%3Dmax%28totalCount%29%0A%20%20%20%20by%0A%20%20%20%20operation%2C%0A%20%20%20%20success%2C%0A%20%20%20%20resultCode%2C%0A%20%20%20%20type%2C%0A%20%20%20%20outerMessage%2C%0A%20%20%20%20target%20%0A%7C%20project%0A%20%20%20%20operation%2C%0A%20%20%20%20target%2C%0A%20%20%20%20failed%2C%0A%20%20%20%20total%2C%0A%20%20%20%20failRateP%3D100.0%20%2A%20failed%20%2F%20total%2C%0A%20%20%20%20resultCode%0A%7C%20render%20timechart%20%0A%7C%20where%20failRateP%20%3E%3D%2010%0A%7C%20where%20total%20%21%3D%20failed%0A%7C%20where%20failed%20%3E%3D%2010%0A%7C%20where%20resultCode%20%3D%3D%20400%7C%20where%20tostring%28failed%29%20%3D%3D%20%40%2791%27%20and%20tostring%28failRateP%29%20%3D%3D%20%40%2791%27%20and%20tostring%28operation%29%20%3D%3D%20%40%27POST%20%2Fv1%2Fcards%2F_%2FpermanentJoin%27%20and%20tostring%28resultCode%29%20%3D%3D%20%40%27400%27%20and%20tostring%28total%29%20%3D%3D%20%40%27100%27&timespan=2023-11-15T08%3a52%3a20.0000000Z%2f2023-11-15T09%3a52%3a20.0000000Z"
    #                         }
    #                     ],
    #                     "windowStartTime":"2023-11-15T08:52:20Z",
    #                     "windowEndTime":"2023-11-15T09:52:20Z"
    #                 }
    #             },
    #             "customProperties":{
                    
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'AI-APIM-PRD')

    # def testServiceHealth(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId":"Microsoft.Insights/activityLogs",
    #         "data":{
    #             "status":"Activated",
    #             "context":{
    #                 "activityLog":{
    #                     "channels":"Admin",
    #                     "correlationId":"11223344-1234-5678-abcd-aabbccddeeff",
    #                     "description":"This alert rule will trigger when there are updates to a service issue impacting subscription <name>.",
    #                     "eventSource":"ServiceHealth",
    #                     "eventTimestamp":"2023-11-13T16:39:47.558Z",
    #                     "eventDataId":"12345678-1234-1234-1234-1234567890ab",
    #                     "level":"Warning",
    #                     "operationName":"Microsoft.ServiceHealth/incident/action",
    #                     "operationId":"12345678-abcd-efgh-ijkl-abcd12345678",
    #                     "properties":{
    #                         "title":"Test Action Group - Test Service Health Alert",
    #                         "service":"Azure Service Name",
    #                         "region":"Global",
    #                         "communication":"<p>This is a test from Service Health Alert</p>",
    #                         "incidentType":"Incident",
    #                         "trackingId":"TEST-TTT",
    #                         "impactStartTime":"2023-11-13T16:39:47.558Z",
    #                         "impactMitigationTime":"2023-11-13T16:39:47.558Z",
    #                         "impactedServices":[
    #                             {
    #                                 "ImpactedRegions":[
    #                                     {
    #                                         "RegionName":"Global"
    #                                     }
    #                                 ],
    #                                 "ServiceName":"Azure Service Name"
    #                             }
    #                         ],
    #                         "impactedServicesTableRows":"<tr><td>This is a test from service health alert</<td>/<tr>",
    #                         "defaultLanguageTitle":"Test Action Group - Test Service Health Alert",
    #                         "defaultLanguageContent":"<p>This is a test from Service Health Alert</p>",
    #                         "stage":"Resolved",
    #                         "communicationId":"11223344556677",
    #                         "isHIR":"false",
    #                         "isSynthetic":"True",
    #                         "impactType":"SubscriptionList",
    #                         "version":"0.1.1"
    #                     },
    #                     "status":"Resolved",
    #                     "subscriptionId":"11111111-1111-1111-1111-111111111111",
    #                     "submissionTimestamp":"2023-11-13T16:39:47.558Z"
    #                 }
    #             },
    #             "properties":{
                    
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'Azure Service Name')

    # def testResourceHealth(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId": "Microsoft.Insights/activityLogs",
    #         "data": {
    #             "status": "Activated",
    #             "context": {
    #                 "activityLog": {
    #                     "channels": "Admin, Operation",
    #                     "correlationId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    #                     "eventSource": "ResourceHealth",
    #                     "eventTimestamp": "2023-11-13T15:45:02.528Z",
    #                     "eventDataId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    #                     "level": "Informational",
    #                     "operationName": "Microsoft.Resourcehealth/healthevent/Activated/action",
    #                     "operationId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    #                     "properties": {
    #                         "title": "Rebooted by user",
    #                         "details": null,
    #                         "currentHealthStatus": "Unavailable",
    #                         "previousHealthStatus": "Available",
    #                         "type": "Downtime",
    #                         "cause": "UserInitiated"
    #                     },
    #                     "resourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test-RG/providers/Microsoft.Compute/virtualMachines/test-VM",
    #                     "resourceGroupName": "test-RG",
    #                     "resourceProviderName": "Microsoft.Resourcehealth/healthevent/action",
    #                     "status": "Active",
    #                     "subscriptionId": "11111111-1111-1111-1111-111111111111",
    #                     "resourceType": "MICROSOFT.COMPUTE/VIRTUALMACHINES"
    #                 }
    #             },
    #             "properties": {
    #                 "customKey1": "value1",
    #                 "customKey2": "value2"
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'test-VM')

    # def testLogAlertV2(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId":"Microsoft.Insights/LogAlert",
    #         "data":{
    #             "data":{
    #                 "essentials":{
    #                     "alertId":"/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.AlertsManagement/alerts/12345678-1234-1234-1234-1234567890ab",
    #                     "alertRule":"test-logAlertRule-v2",
    #                     "severity":"Sev3",
    #                     "signalType":"Log",
    #                     "monitorCondition":"Fired",
    #                     "monitoringService":"Log Alerts V2",
    #                     "alertTargetIDs":[
    #                         "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/test-RG/providers/microsoft.operationalinsights/workspaces/test-logAnalyticsWorkspace"
    #                     ],
    #                     "configurationItems":[
    #                         "test-computer"
    #                     ],
    #                     "originAlertId":"22222222-2222-2222-2222-222222222222",
    #                     "firedDateTime":"2023-11-13T12:45:46.354Z",
    #                     "description":"Alert rule description",
    #                     "essentialsVersion":"1.0",
    #                     "alertContextVersion":"1.0"
    #                 },
    #                 "alertContext":{
    #                     "properties":{
    #                         "customKey1":"value1",
    #                         "customKey2":"value2"
    #                     },
    #                     "conditionType":"LogQueryCriteria",
    #                     "condition":{
    #                         "windowSize":"PT1H",
    #                         "allOf":[
    #                             {
    #                                 "searchQuery":"Heartbeat",
    #                                 "metricMeasureColumn":null,
    #                                 "targetResourceTypes":"['Microsoft.OperationalInsights/workspaces']",
    #                                 "operator":"GreaterThan",
    #                                 "threshold":"0",
    #                                 "timeAggregation":"Count",
    #                                 "dimensions":[
    #                                     {
    #                                         "name":"Computer",
    #                                         "value":"test-computer"
    #                                     }
    #                                 ],
    #                                 "metricValue":3.0,
    #                                 "failingPeriods":{
    #                                     "numberOfEvaluationPeriods":1,
    #                                     "minFailingPeriodsToAlert":1
    #                                 },
    #                                 "linkToSearchResultsUI":"https://portal.azure.com#@.../prettify/1/timespan/2021-11-16T10%3a17%3a39.0000000Z%2f2021-11-16T11%3a17%3a39.0000000Z",
    #                                 "linkToFilteredSearchResultsUI":"https://portal.azure.com#@.../prettify/1/timespan/2021-11-16T10%3a17%3a39.0000000Z%2f2021-11-16T11%3a17%3a39.0000000Z",
    #                                 "linkToSearchResultsAPI":"https://api.loganalytics.io/v1/workspaces/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/query?query=Heartbeat%7C%20where%20TimeGenerated%20between%28datetime%282021-11-16T10%3A17%3A39.0000000Z%29..datetime%282021-11-16T11%3A17%3A39.0000000Z%29%29&timespan=2021-11-16T10%3a17%3a39.0000000Z%2f2021-11-16T11%3a17%3a39.0000000Z",
    #                                 "linkToFilteredSearchResultsAPI":"https://api.loganalytics.io/v1/workspaces/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/query?query=Heartbeat%7C%20where%20TimeGenerated%20between%28datetime%282021-11-16T10%3A17%3A39.0000000Z%29..datetime%282021-11-16T11%3A17%3A39.0000000Z%29%29%7C%20where%20tostring%28Computer%29%20%3D%3D%20%27test-computer%27&timespan=2021-11-16T10%3a17%3a39.0000000Z%2f2021-11-16T11%3a17%3a39.0000000Z"
    #                             }
    #                         ],
    #                         "windowStartTime":"2023-11-13T12:45:46.354Z",
    #                         "windowEndTime":"2023-11-13T12:45:46.354Z"
    #                     }
    #                 }
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'test-computer')

    def testLogAlert(self):
        common_metric_alert = r"""
        {
            "schemaId": "Microsoft.Insights/LogAlert",
            "data": {
                "SubscriptionId": "11111111-1111-1111-1111-111111111111",
                "AlertRuleName": "test-logAlertRule-v1-metricMeasurement",
                "SearchQuery": "Heartbeat | summarize AggregatedValue=count() by bin(TimeGenerated, 5m)",
                "SearchIntervalStartTimeUtc": "2023-11-13T11:53:01.199Z",
                "SearchIntervalEndtimeUtc": "2023-11-13T11:53:01.199Z",
                "AlertThresholdOperator": "Greater Than",
                "AlertThresholdValue": 0,
                "ResultCount": 2,
                "SearchIntervalInSeconds": 86400,
                "LinkToSearchResults": "https://portal.azure.com@aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/source/Alerts.EmailLinks/scope/%7B%22resources%22%3A%5B%7B%22resourceId%22%3A%22%2Fsubscriptions%2F11111111-1111-1111-1111-111111111111%2FresourceGroups%2Ftest-RG%2Fproviders%2FMicrosoft.OperationalInsights%2Fworkspaces%2Ftest-logAnalyticsWorkspace%22%7D%5D%7D/q/aBcDeFgHi%2BWqaBcDeFgHiMqsSlVwTE8vSk1PLElNCUvMKU2aBcDeFgHiaBcDeFgHiaBcDeFgHiaBcDeFgHiaBcDeFgHi/prettify/1/timespan/2021-11-15T15%3a16%3a49.0000000Z%2f2021-11-16T15%3a16%3a49.0000000Z",
                "LinkToFilteredSearchResultsUI": "https://portal.azure.com@aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/source/Alerts.EmailLinks/scope/%7B%22resources%22%3A%5B%7B%22resourceId%22%3A%22%2Fsubscriptions%2F11111111-1111-1111-1111-111111111111%2FresourceGroups%2Ftest-RG%2Fproviders%2FMicrosoft.OperationalInsights%2Fworkspaces%2Ftest-logAnalyticsWorkspace%22%7D%5D%7D/q/aBcDeFgHiaBcDeFgHiaBcDeFgHiTP1DtWhcTfIApUfTx0dp%2BOPOhDKsHR%2FFeJXsaBcDeFgHiaBcDeFgHiaBcDeFgHiaBcDeFgHiaBcDeFgHiaBcDeFgHiRI9mhc%3D/prettify/1/timespan/2021-11-15T15%3a16%3a49.0000000Z%2f2021-11-16T15%3a16%3a49.0000000Z",
                "LinkToSearchResultsAPI": "https://api.loganalytics.io/v1/workspaces/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/query?query=Heartbeat%20%0A%7C%20summarize%20AggregatedValue%3Dcount%28%29%20by%20bin%28TimeGenerated%2C%205m%29&timespan=2021-11-15T15%3a16%3a49.0000000Z%2f2021-11-16T15%3a16%3a49.0000000Z",
                "LinkToFilteredSearchResultsAPI": "https://api.loganalytics.io/v1/workspaces/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/query?query=Heartbeat%20%0A%7C%20summarize%20AggregatedValue%3Dcount%28%29%20by%20bin%28TimeGenerated%2C%205m%29%7C%20where%20todouble%28AggregatedValue%29%20%3E%200&timespan=2021-11-15T15%3a16%3a49.0000000Z%2f2021-11-16T15%3a16%3a49.0000000Z",
                "Description": "Alert rule description",
                "Severity": "3",
                "SearchResult": {
                    "tables": [
                        {
                            "name": "PrimaryResult",
                            "columns": [
                                {
                                    "name": "TimeGenerated",
                                    "type": "datetime"
                                },
                                {
                                    "name": "AggregatedValue",
                                    "type": "long"
                                }
                            ],
                            "rows": [
                                [
                                    "2023-11-13T11:53:01.199Z",
                                    11
                                ],
                                [
                                    "2023-11-13T11:53:01.199Z",
                                    11
                                ]
                            ]
                        }
                    ],
                    "dataSources": [
                        {
                            "resourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/test-RG/providers/microsoft.operationalinsights/workspaces/test-logAnalyticsWorkspace",
                            "region": "eastus",
                            "tables": [
                                "Heartbeat"
                            ]
                        }
                    ]
                },
                "WorkspaceId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "ResourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test-RG/providers/Microsoft.OperationalInsights/workspaces/test-logAnalyticsWorkspace",
                "AlertType": "Metric measurement",
                "Dimensions": []
            }
        }
        """

        response = self.client.post(
            '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
        self.assertEqual(response.status_code, 201, response.data)
        data = json.loads(response.data.decode('utf-8'))
        print(json.dumps(data, indent=4))
        self.assertEqual(data['alert']['resource'], 'test-logAnalyticsWorkspace')

    # def testCostBudgetAlert(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId": "AIP Budget Notification",
    #         "data": {
    #             "SubscriptionName": "test-subscription",
    #             "SubscriptionId": "11111111-1111-1111-1111-111111111111",
    #             "EnrollmentNumber": "",
    #             "DepartmentName": "test-budgetDepartmentName",
    #             "AccountName": "test-budgetAccountName",
    #             "BillingAccountId": "",
    #             "BillingProfileId": "",
    #             "InvoiceSectionId": "",
    #             "ResourceGroup": "test-RG",
    #             "SpendingAmount": "1111.32",
    #             "BudgetStartDate": "2023-11-13T10:52:20.381Z",
    #             "Budget": "10000",
    #             "Unit": "USD",
    #             "BudgetCreator": "email@domain.com",
    #             "BudgetName": "test-budgetName",
    #             "BudgetType": "Cost",
    #             "NotificationThresholdAmount": "8000.0"
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'test-budgetName')
    
    # def testAvailabilityAlert(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId": "AzureMonitorMetricAlert",
    #         "data": {
    #             "data": {
    #                 "version": "2.0",
    #                 "properties": {
    #                     "customKey1": "value1",
    #                     "customKey2": "value2"
    #                 },
    #                 "status": "Activated",
    #                 "context": {
    #                     "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/test-RG/providers/microsoft.insights/metricalerts/test-availabilityTest-test-applicationInsights",
    #                     "name": "test-availabilityTest-test-applicationInsights",
    #                     "description": "Alert rule description",
    #                     "conditionType": "WebtestLocationAvailabilityCriteria",
    #                     "severity": "1",
    #                     "condition": {
    #                         "windowSize": "PT5M",
    #                         "allOf": [
    #                             {
    #                                 "metricName": "Failed Location",
    #                                 "metricNamespace": null,
    #                                 "operator": "GreaterThan",
    #                                 "threshold": "2",
    #                                 "timeAggregation": "Sum",
    #                                 "dimensions": [],
    #                                 "metricValue": 5.0,
    #                                 "webTestName": "test-availabilityTest-test-applicationInsights"
    #                             }
    #                         ]
    #                     },
    #                     "subscriptionId": "11111111-1111-1111-1111-111111111111",
    #                     "resourceGroupName": "test-RG",
    #                     "resourceName": "test-availabilityTest-test-applicationInsights",
    #                     "resourceType": "microsoft.insights/webtests",
    #                     "resourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/test-RG/providers/microsoft.insights/webtests/test-availabilityTest-test-applicationInsights",
    #                     "portalLink": "https://portal.azure.com/resource/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/test-RG/providers/microsoft.insights/webtests/test-availabilityTest-test-applicationInsights"
    #                 }
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'test-availabilityTest-test-applicationInsights')

    # def testActivityLog(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId": "Microsoft.Insights/activityLogs",
    #         "data": {
    #             "status": "Activated",
    #             "context": {
    #                 "activityLog": {
    #                     "authorization": {
    #                         "action": "Microsoft.Compute/virtualMachines/restart/action",
    #                         "scope": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test-RG/providers/Microsoft.Compute/virtualMachines/test-VM3"
    #                     },
    #                     "channels": "Operation",
    #                     "claims": "{}",
    #                     "caller": "user-email@domain.com",
    #                     "correlationId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    #                     "description": "",
    #                     "eventSource": "Administrative",
    #                     "eventTimestamp": "2023-11-13T09:26:42.848Z",
    #                     "eventDataId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    #                     "level": "Informational",
    #                     "operationName": "Microsoft.Compute/virtualMachines/restart/action",
    #                     "operationId": "cccccccc-cccc-cccc-cccc-cccccccccccc",
    #                     "properties": {
    #                         "eventCategory": "Administrative",
    #                         "entity": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test-RG/providers/Microsoft.Compute/virtualMachines/test-VM",
    #                         "message": "Microsoft.Compute/virtualMachines/restart/action",
    #                         "hierarchy": "22222222-2222-2222-2222-222222222222/CnAIOrchestrationServicePublicCorpprod/33333333-3333-3333-3333-3333333303333/44444444-4444-4444-4444-444444444444/55555555-5555-5555-5555-555555555555/11111111-1111-1111-1111-111111111111"
    #                     },
    #                     "resourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/test-RG/providers/Microsoft.Compute/virtualMachines/test-VM",
    #                     "resourceGroupName": "test-RG",
    #                     "resourceProviderName": "Microsoft.Compute",
    #                     "status": "Succeeded",
    #                     "subStatus": "",
    #                     "subscriptionId": "11111111-1111-1111-1111-111111111111",
    #                     "submissionTimestamp": "2023-11-13T09:26:42.848Z",
    #                     "resourceType": "Microsoft.Compute/virtualMachines"
    #                 }
    #             },
    #             "properties": {
    #                 "customKey1": "value1",
    #                 "customKey2": "value2"
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'test-VM3')
    
    # def test_azure_service_health_common(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId": "azureMonitorCommonAlertSchema",
    #         "data": {
    #             "essentials": {
    #                 "alertId": "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.AlertsManagement/alerts/1234abcd5678efgh1234abcd5678efgh1234abcd5678efgh1234abcd5678efgh",
    #                 "alertRule": "test-ServiceHealthAlertRule",
    #                 "severity": "Sev4",
    #                 "signalType": "Activity Log",
    #                 "monitorCondition": "Fired",
    #                 "monitoringService": "ServiceHealth",
    #                 "alertTargetIDs": [
    #                     "/subscriptions/11111111-1111-1111-1111-111111111111"
    #                 ],
    #                 "originAlertId": "12345678-1234-1234-1234-1234567890ab",
    #                 "firedDateTime": "2023-11-08T09:04:23.598Z",
    #                 "description": "Alert rule description",
    #                 "essentialsVersion": "1.0",
    #                 "alertContextVersion": "1.0"
    #             },
    #             "alertContext": {
    #                 "authorization": null,
    #                 "channels": 1,
    #                 "claims": null,
    #                 "caller": null,
    #                 "correlationId": "12345678-abcd-efgh-ijkl-abcd12345678",
    #                 "eventSource": 2,
    #                 "eventTimestamp": "2023-11-08T09:04:23.598Z",
    #                 "httpRequest": null,
    #                 "eventDataId": "12345678-1234-1234-1234-1234567890ab",
    #                 "level": 3,
    #                 "operationName": "Microsoft.ServiceHealth/incident/action",
    #                 "operationId": "12345678-abcd-efgh-ijkl-abcd12345678",
    #                 "properties": {
    #                     "title": "Test Action Group - Test Service Health Alert",
    #                     "service": "Azure Service Name",
    #                     "region": "Global",
    #                     "communication": "<p>This is a test from Service Health Alert</p>",
    #                     "incidentType": "Incident",
    #                     "trackingId": "TEST-TTT",
    #                     "impactStartTime": "2023-11-08T09:04:23.598Z",
    #                     "impactMitigationTime": "2023-11-08T09:04:23.598Z",
    #                     "impactedServices": [
    #                         {
    #                             "ImpactedRegions": [
    #                                 {
    #                                     "RegionName": "Global"
    #                                 }
    #                             ],
    #                             "ServiceName": "Azure Service Name"
    #                         }
    #                     ],
    #                     "impactedServicesTableRows": "<tr><td>This is a test from service health alert</td></tr>",
    #                     "defaultLanguageTitle": "Test Action Group - Test Service Health Alert",
    #                     "defaultLanguageContent": "<p>This is a test from Service Health Alert</p>",
    #                     "stage": "Resolved",
    #                     "communicationId": "11223344556677",
    #                     "isHIR": "false",
    #                     "IsSynthetic": "True",
    #                     "impactType": "SubscriptionList",
    #                     "version": "0.1.1"
    #                 },
    #                 "status": "Resolved",
    #                 "subStatus": null,
    #                 "submissionTimestamp": "2023-11-08T09:04:23.598Z",
    #                 "ResourceType": null
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'Azure Service Name')

    # def test_azure_log_alert_v1_common(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId": "azureMonitorCommonAlertSchema",
    #         "data": {
    #             "essentials": {
    #                 "alertId": "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.AlertsManagement/alerts/12345678-1234-1234-1234-1234567890ab",
    #                 "alertRule": "test-logAlertRule-v1-metricMeasurement",
    #                 "severity": "Sev3",
    #                 "signalType": "Log",
    #                 "monitorCondition": "Fired",
    #                 "monitoringService": "Log Analytics",
    #                 "alertTargetIDs": [
    #                     "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/test-RG/providers/microsoft.operationalinsights/workspaces/test-logAnalyticsWorkspace"
    #                 ],
    #                 "configurationItems": [],
    #                 "originAlertId": "12345678-4444-4444-4444-1234567890ab",
    #                 "firedDateTime": "2023-11-08T08:21:58.861Z",
    #                 "description": "Alert rule description",
    #                 "essentialsVersion": "1.0",
    #                 "alertContextVersion": "1.1"
    #             },
    #             "alertContext": {
    #                 "SearchQuery": "Heartbeat | summarize AggregatedValue=count() by bin(TimeGenerated, 5m)",
    #                 "SearchIntervalStartTimeUtc": "2023-11-08T08:21:58.861Z",
    #                 "SearchIntervalEndtimeUtc": "2023-11-08T08:21:58.861Z",
    #                 "ResultCount": 2,
    #                 "LinkToSearchResults": "https://portal.azure.com@aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/source/Alerts.EmailLinks/scope/%7B%22resources%22%3A%5B%7B%22resourceId%22%3A%22%2Fsubscriptions%2F11111111-1111-1111-1111-111111111111%2FresourceGroups%2Ftest-RG%2Fproviders%2FMicrosoft.OperationalInsights%2Fworkspaces%2Ftest-logAnalyticsWorkspace%22%7D%5D%7D/q/aBcDeFgHi%2BWqUSguzc1NLMqsSlVwTE8vSk1PLElNCUvMKU21Tc4vzSvRaBcDeFgHiaBcDeFgHiaBcDeFgHiaBcDeFgHi/prettify/1/timespan/2021-11-15T15%3a16%3a49.0000000Z%2f2021-11-16T15%3a16%3a49.0000000Z",
    #                 "LinkToFilteredSearchResultsUI": "https://portal.azure.com@aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/blade/Microsoft_Azure_Monitoring_Logs/LogsBlade/source/Alerts.EmailLinks/scope/%7B%22resources%22%3A%5B%7B%22resourceId%22%3A%22%2Fsubscriptions%2F11111111-1111-1111-1111-111111111111%2FresourceGroups%2Ftest-RG%2Fproviders%2FMicrosoft.OperationalInsights%2Fworkspaces%2Ftest-logAnalyticsWorkspace%22%7D%5D%7D/q/aBcDeFgHiaBcDeFgHiaBcDeFgHiaBcDeFgHiaBcDeFgHidp%2BOPOhDKsHR%2FFeJXsTgzGJRmVui3KF3RpLyEJCX9A2iMl6jgxMn6jRevng3JmIHLdYtKP4DRI9mhc%3D/prettify/1/timespan/2021-11-15T15%3a16%3a49.0000000Z%2f2021-11-16T15%3a16%3a49.0000000Z",
    #                 "LinkToSearchResultsAPI": "https://api.loganalytics.io/v1/workspaces/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/queryquery=Heartbeat%20%0A%7C%20summarize%20AggregatedValue%3Dcount%28%29%20by%20bin%28TimeGenerated%2C%205m%29&timespan=2021-11-15T15%3a16%3a49.0000000Z%2f2021-11-16T15%3a16%3a49.0000000Z",
    #                 "LinkToFilteredSearchResultsAPI": "https://api.loganalytics.io/v1/workspaces/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/queryquery=Heartbeat%20%0A%7C%20summarize%20AggregatedValue%3Dcount%28%29%20by%20bin%28TimeGenerated%2C%205m%29%7C%20where%20todouble%28AggregatedValue%29%20%3E%200&timespan=2021-11-15T15%3a16%3a49.0000000Z%2f2021-11-16T15%3a16%3a49.0000000Z",
    #                 "SeverityDescription": "Informational",
    #                 "WorkspaceId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    #                 "SearchIntervalDurationMin": "1440",
    #                 "AffectedConfigurationItems": [],
    #                 "AlertType": "Metric measurement",
    #                 "IncludeSearchResults": true,
    #                 "Dimensions": [],
    #                 "SearchIntervalInMinutes": "1440",
    #                 "SearchResults": {
    #                     "tables": [
    #                         {
    #                             "name": "PrimaryResult",
    #                             "columns": [
    #                                 {
    #                                     "name": "TimeGenerated",
    #                                     "type": "datetime"
    #                                 },
    #                                 {
    #                                     "name": "AggregatedValue",
    #                                     "type": "long"
    #                                 }
    #                             ],
    #                             "rows": [
    #                                 [
    #                                     "2023-11-08T08:21:58.861Z",
    #                                     11
    #                                 ],
    #                                 [
    #                                     "2023-11-08T08:21:58.861Z",
    #                                     11
    #                                 ]
    #                             ]
    #                         }
    #                     ],
    #                     "dataSources": [
    #                         {
    #                             "resourceId": "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/test-RG/providers/microsoft.operationalinsights/workspaces/test-logAnalyticsWorkspace",
    #                             "region": "eastus",
    #                             "tables": [
    #                                 "Heartbeat"
    #                             ]
    #                         }
    #                     ]
    #                 },
    #                 "Threshold": 0,
    #                 "Operator": "Greater Than",
    #                 "IncludedSearchResults": "True"
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     # print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'test-logAnalyticsWorkspace')

    # def test_azure_common_budget(self):
    #     common_metric_alert = r"""
    #     {
    #         "schemaId": "azureMonitorCommonAlertSchema",
    #         "data": {
    #             "essentials": {
    #                 "monitoringService": "CostAlerts",
    #                 "firedDateTime": "2023-11-08T08:13:18.509Z",
    #                 "description": "Your spend for budget Test_actual_cost_budget is now $11,111.00 exceeding your specified threshold $25.00.",
    #                 "essentialsVersion": "1.0",
    #                 "alertContextVersion": "1.0",
    #                 "alertId": "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.CostManagement/alerts/Test_Alert",
    #                 "alertRule": null,
    #                 "severity": null,
    #                 "signalType": null,
    #                 "monitorCondition": null,
    #                 "alertTargetIDs": null,
    #                 "configurationItems": [
    #                     "budgets"
    #                 ],
    #                 "originAlertId": null
    #             },
    #             "alertContext": {
    #                 "AlertCategory": "budgets",
    #                 "AlertData": {
    #                     "Scope": "/subscriptions/11111111-1111-1111-1111-111111111111/",
    #                     "ThresholdType": "Actual",
    #                     "BudgetType": "Cost",
    #                     "BudgetThreshold": "$50.00",
    #                     "NotificationThresholdAmount": "$25.00",
    #                     "BudgetName": "Test_actual_cost_budget",
    #                     "BudgetId": "/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.Consumption/budgets/Test_actual_cost_budget",
    #                     "BudgetStartDate": "2022-11-01",
    #                     "BudgetCreator": "test@sample.test",
    #                     "Unit": "USD",
    #                     "SpentAmount": "$11,111.00"
    #                 }
    #             }
    #         }
    #     }

    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     # print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'budgets')

    # def test_azure_monitor_common(self):
        
    #     common_metric_alert = r"""
    #     {
    #         "schemaId":"azureMonitorCommonAlertSchema",
    #         "data":{
    #             "essentials":{
    #                 "alertId":"/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.AlertsManagement/alerts/12345678-1234-1234-1234-1234567890ab",
    #                 "alertRule":"test-ResourceHealthAlertRule",
    #                 "severity":"Sev4",
    #                 "signalType":"Activity Log",
    #                 "monitorCondition":"Fired",
    #                 "monitoringService":"Resource Health",
    #                 "alertTargetIDs":[
    #                     "/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/test-RG/providers/microsoft.compute/virtualmachines/test-VM"
    #                 ],
    #                 "configurationItems":[
    #                     "test-VM"
    #                 ],
    #                 "originAlertId":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb_123456789012345678901234567890ab",
    #                 "firedDateTime":"2023-11-07T08:39:43.111Z",
    #                 "description":"Alert rule description",
    #                 "essentialsVersion":"1.0",
    #                 "alertContextVersion":"1.0"
    #             },
    #             "alertContext":{
    #                 "channels":"Admin, Operation",
    #                 "correlationId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    #                 "eventSource":"ResourceHealth",
    #                 "eventTimestamp":"2023-11-07T08:39:43.111Z",
    #                 "eventDataId":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    #                 "level":"Informational",
    #                 "operationName":"Microsoft.Resourcehealth/healthevent/Activated/action",
    #                 "operationId":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    #                 "properties":{
    #                     "title":"Rebooted by user",
    #                     "details":null,
    #                     "currentHealthStatus":"Unavailable",
    #                     "previousHealthStatus":"Available",
    #                     "type":"Downtime",
    #                     "cause":"UserInitiated"
    #                 },
    #                 "status":"Active",
    #                 "submissionTimestamp":"2023-11-07T08:39:43.111Z",
    #                 "Activity Log Event Description":null
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     # print(json.dumps(data, indent=4))
    #     self.assertEqual(data['alert']['resource'], 'test-VM')

    #     common_metric_alert = r"""
    #     {
    #         "schemaId": "azureMonitorCommonAlertSchema",
    #         "data": {
    #             "essentials": {
    #                 "alertId": "/subscriptions/<subscription ID>/providers/Microsoft.AlertsManagement/alerts/b9569717-bc32-442f-add5-83a997729330",
    #                 "alertRule": "WCUS-R2-Gen2",
    #                 "severity": "Sev3",
    #                 "signalType": "Metric",
    #                 "monitorCondition": "Resolved",
    #                 "monitoringService": "Platform",
    #                 "alertTargetIDs": [
    #                     "/subscriptions/<subscription ID>/resourcegroups/pipelinealertrg/providers/microsoft.compute/virtualmachines/wcus-r2-gen2"
    #                 ],
    #                 "configurationItems": [
    #                     "wcus-r2-gen2"
    #                 ],
    #                 "originAlertId": "3f2d4487-b0fc-4125-8bd5-7ad17384221e_PipeLineAlertRG_microsoft.insights_metricAlerts_WCUS-R2-Gen2_-117781227",
    #                 "firedDateTime": "2019-03-22T13:58:24.3713213Z",
    #                 "resolvedDateTime": "2019-03-22T14:03:16.2246313Z",
    #                 "description": "",
    #                 "essentialsVersion": "1.0",
    #                 "alertContextVersion": "1.0"
    #             },
    #             "alertContext": {
    #             "properties": null,
    #             "conditionType": "SingleResourceMultipleMetricCriteria",
    #             "condition": {
    #                 "windowSize": "PT5M",
    #                 "allOf": [
    #                 {
    #                     "metricName": "Percentage CPU",
    #                     "metricNamespace": "Microsoft.Compute/virtualMachines",
    #                     "operator": "GreaterThan",
    #                     "threshold": "25",
    #                     "timeAggregation": "Average",
    #                     "dimensions": [
    #                     {
    #                         "name": "ResourceId",
    #                         "value": "3efad9dc-3d50-4eac-9c87-8b3fd6f97e4e"
    #                     }
    #                     ],
    #                     "metricValue": 7.727
    #                 }
    #                 ]
    #             }
    #             },
    #             "customProperties": {
    #             "Key1": "Value1",
    #             "Key2": "Value2"
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=common_metric_alert, content_type='application/json')
    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     self.assertEqual(data['alert']['resource'], 'wcus-r2-gen2')

    # def test_azuremonitor_webhook_classic(self):
    #     """ See https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-webhooks """

    #     classic_metric_alert = r"""
    #     {
    #         "status": "Activated",
    #         "context": {
    #             "timestamp": "2015-08-14T22:26:41.9975398Z",
    #             "id": "/subscriptions/s1/resourceGroups/useast/providers/microsoft.insights/alertrules/ruleName1",
    #             "name": "ruleName1",
    #             "description": "some description",
    #             "conditionType": "Metric",
    #             "condition": {
    #                 "metricName": "Requests",
    #                 "metricUnit": "Count",
    #                 "metricValue": "10",
    #                 "threshold": "10",
    #                 "windowSize": "15",
    #                 "timeAggregation": "Average",
    #                 "operator": "GreaterThanOrEqual"
    #             },
    #             "subscriptionId": "s1",
    #             "resourceGroupName": "useast",
    #             "resourceName": "mysite1",
    #             "resourceType": "microsoft.foo/sites",
    #             "resourceId": "/subscriptions/s1/resourceGroups/useast/providers/microsoft.foo/sites/mysite1",
    #             "resourceRegion": "centralus",
    #             "portalLink": "https://portal.azure.com/#resource/subscriptions/s1/resourceGroups/useast/providers/microsoft.foo/sites/mysite1"
    #         },
    #         "properties": {
    #             "key1": "value1",
    #             "key2": "value2"
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=classic_metric_alert, content_type='application/json')

    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     self.assertEqual(data['alert']['resource'], 'mysite1')
    #     self.assertEqual(data['alert']['event'], 'ruleName1')
    #     self.assertEqual(data['alert']['environment'], 'Production')
    #     self.assertEqual(data['alert']['severity'], 'critical')
    #     self.assertEqual(data['alert']['status'], 'open')
    #     self.assertEqual(data['alert']['service'], ['microsoft.foo/sites'])
    #     self.assertEqual(data['alert']['group'], 'useast')
    #     self.assertEqual(data['alert']['value'], '10 Requests')
    #     self.assertEqual(data['alert']['text'],
    #                      'CRITICAL: 10 Requests (GreaterThanOrEqual 10)')
    #     self.assertEqual(sorted(data['alert']['tags']), [
    #                      'key1=value1', 'key2=value2'])

    #     classic_metric_alert = r"""
    #     {
    #         "status": "Activated",
    #         "context": {
    #             "id": "/subscriptions/1a66ce04-b633-4a0b-b2bc-a912ec8986a6/resourceGroups/montest/providers/microsoft.insights/alertrules/Alert_1_runscope12",
    #             "name": "Alert_1_runscope12",
    #             "description": "desc",
    #             "conditionType": "Metric",
    #             "condition": {
    #                 "metricName": "Memory available",
    #                 "metricUnit": "Bytes",
    #                 "metricValue": "1032190976",
    #                 "threshold": "2",
    #                 "windowSize": "5",
    #                 "timeAggregation": "Average",
    #                 "operator": "GreaterThan"
    #             },
    #             "subscriptionId": "1a66ce04-b633-4a0b-b2bc-a912ec8986a6",
    #             "resourceGroupName": "montest",
    #             "timestamp": "2015-09-18T01:02:35.8190994Z",
    #             "resourceName": "helixtest1",
    #             "resourceType": "microsoft.compute/virtualmachines",
    #             "resourceId": "/subscriptions/1a66ce04-b633-4a0b-b2bc-a912ec8986a6/resourceGroups/montest/providers/Microsoft.Compute/virtualMachines/Helixtest1",
    #             "resourceRegion": "centralus",
    #             "portalLink": "http://portallink.com"
    #         },
    #         "properties": {
    #             "hello1": "World1!",
    #             "json_stuff": {
    #                 "color": "red"
    #             },
    #             "customId": "wd39ue9832ue9iuhd9iuewhd9edh",
    #             "send_emails_to": "someone@somewhere.com"
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=classic_metric_alert, content_type='application/json')

    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     self.assertEqual(data['alert']['resource'], 'helixtest1')
    #     self.assertEqual(data['alert']['event'], 'Alert_1_runscope12')
    #     self.assertEqual(data['alert']['environment'], 'Production')
    #     self.assertEqual(data['alert']['severity'], 'critical')
    #     self.assertEqual(data['alert']['status'], 'open')
    #     self.assertEqual(data['alert']['service'], [
    #                      'microsoft.compute/virtualmachines'])
    #     self.assertEqual(data['alert']['group'], 'montest')
    #     self.assertEqual(data['alert']['value'], '1032190976 Memory available')
    #     self.assertEqual(
    #         data['alert']['text'], 'CRITICAL: 1032190976 Memory available (GreaterThan 2)')
    #     self.assertEqual(sorted(data['alert']['tags']), [
    #         'customId=wd39ue9832ue9iuhd9iuewhd9edh',
    #         'hello1=World1!',
    #         "json_stuff={'color': 'red'}",
    #         'send_emails_to=someone@somewhere.com']
    #     )

    # def test_azuremonitor_webhook_new(self):
    #     """ See https://docs.microsoft.com/en-us/azure/azure-monitor/platform/alerts-metric-near-real-time """

    #     new_metric_alert = r"""
    #     {
    #         "schemaId": "AzureMonitorMetricAlert",
    #         "data": {
    #             "version": "2.0",
    #             "status": "Activated",
    #             "context": {
    #                 "timestamp": "2018-02-28T10:44:10.1714014Z",
    #                 "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Contoso/providers/microsoft.insights/metricAlerts/StorageCheck",
    #                 "name": "StorageCheck",
    #                 "description": "",
    #                 "conditionType": "SingleResourceMultipleMetricCriteria",
    #                 "condition": {
    #                     "windowSize": "PT5M",
    #                     "allOf": [
    #                         {
    #                             "metricName": "Transactions",
    #                             "dimensions": [
    #                                 {
    #                                     "name": "AccountResourceId",
    #                                     "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Contoso/providers/Microsoft.Storage/storageAccounts/diag500"
    #                                 },
    #                                 {
    #                                     "name": "GeoType",
    #                                     "value": "Primary"
    #                                 }
    #                             ],
    #                             "operator": "GreaterThan",
    #                             "threshold": "0",
    #                             "timeAggregation": "PT5M",
    #                             "metricValue": 1
    #                         }
    #                     ]
    #                 },
    #                 "subscriptionId": "00000000-0000-0000-0000-000000000000",
    #                 "resourceGroupName": "Contoso",
    #                 "resourceName": "diag500",
    #                 "resourceType": "Microsoft.Storage/storageAccounts",
    #                 "resourceId": "/subscriptions/1e3ff1c0-771a-4119-a03b-be82a51e232d/resourceGroups/Contoso/providers/Microsoft.Storage/storageAccounts/diag500",
    #                 "portalLink": "https://portal.azure.com/#resource//subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Contoso/providers/Microsoft.Storage/storageAccounts/diag500"
    #             },
    #             "properties": {
    #                 "key1": "value1",
    #                 "key2": "value2"
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post(
    #         '/webhooks/azuremonitor', data=new_metric_alert, content_type='application/json')

    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     self.assertEqual(data['alert']['resource'], 'diag500')
    #     self.assertEqual(data['alert']['event'], 'StorageCheck')
    #     self.assertEqual(data['alert']['environment'], 'Production')
    #     self.assertEqual(data['alert']['severity'], 'informational')
    #     self.assertEqual(data['alert']['status'], 'open')
    #     self.assertEqual(data['alert']['service'], [
    #                      'Microsoft.Storage/storageAccounts'])
    #     self.assertEqual(data['alert']['group'], 'Contoso')
    #     self.assertEqual(data['alert']['value'], '1 Transactions')
    #     self.assertEqual(data['alert']['text'],
    #                      'INFORMATIONAL: 1 Transactions (GreaterThan 0)')
    #     self.assertEqual(sorted(data['alert']['tags']), [
    #                      'key1=value1', 'key2=value2'])

    #     new_metric_alert = r"""
    #     {
    #         "schemaId": "AzureMonitorMetricAlert",
    #         "data": {
    #             "version": "2.0",
    #             "properties": null,
    #             "status": "Deactivated",
    #             "context": {
    #                 "timestamp": "2019-02-27T14:10:35.0816694Z",
    #                 "id": "/subscriptions/ba364c14-1aa5-484e-8b74-6201540087e1/resourceGroups/Web/providers/microsoft.insights/metricAlerts/Percentage%20CPU%20greater%20than%2070",
    #                 "name": "CpuUtilHigh",
    #                 "description": "",
    #                 "conditionType": "MultipleResourceMultipleMetricCriteria",
    #                 "severity": "3",
    #                 "condition": {
    #                     "windowSize": "PT5M",
    #                     "allOf": [
    #                         {
    #                             "metricName": "Percentage CPU",
    #                             "metricNamespace": "Microsoft.Compute/virtualMachines",
    #                             "operator": "GreaterThan",
    #                             "threshold": "90",
    #                             "timeAggregation": "Maximum",
    #                             "dimensions": [
    #                                 {
    #                                     "name": "microsoft.resourceId",
    #                                     "value": "/subscriptions/ba364c14-1aa5-484e-8b74-6201540087e1/resourceGroups/Web/providers/Microsoft.Compute/virtualMachines/web01"
    #                                 },
    #                                 {
    #                                     "name": "microsoft.resourceType",
    #                                     "value": "Microsoft.Compute/virtualMachines"
    #                                 }
    #                             ],
    #                             "metricValue": 85
    #                         }
    #                     ]
    #                 },
    #                 "subscriptionId": "ba364c14-1aa5-484e-8b74-6201540087e1",
    #                 "resourceGroupName": "Web",
    #                 "resourceName": "web01",
    #                 "resourceType": "Microsoft.Compute/virtualMachines",
    #                 "resourceId": "/subscriptions/ba364c14-1aa5-484e-8b74-6201540087e1/resourceGroups/Web/providers/Microsoft.Compute/virtualMachines/web01",
    #                 "portalLink": "https://portal.azure.com/#resource/subscriptions/ba364c14-1aa5-484e-8b74-6201540087e1/resourceGroups/Web/providers/Microsoft.Compute/virtualMachines/web01"
    #             }
    #         }
    #     }
    #     """

    #     response = self.client.post('/webhooks/azuremonitor?environment=Development',
    #                                 data=new_metric_alert, content_type='application/json')

    #     self.assertEqual(response.status_code, 201, response.data)
    #     data = json.loads(response.data.decode('utf-8'))
    #     self.assertEqual(data['alert']['resource'], 'web01')
    #     self.assertEqual(data['alert']['event'], 'CpuUtilHigh')
    #     self.assertEqual(data['alert']['environment'], 'Development')
    #     self.assertEqual(data['alert']['severity'], 'ok')
    #     self.assertEqual(data['alert']['status'], 'closed')
    #     self.assertEqual(data['alert']['service'], [
    #                      'Microsoft.Compute/virtualMachines'])
    #     self.assertEqual(data['alert']['group'], 'Web')
    #     self.assertEqual(data['alert']['value'], '85 Percentage CPU')
    #     self.assertEqual(data['alert']['text'],
    #                      'OK: 85 Percentage CPU (GreaterThan 90)')
    #     self.assertEqual(sorted(data['alert']['tags']), [])
