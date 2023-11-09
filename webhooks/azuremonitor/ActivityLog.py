import re
from dateutil.parser import parse as parse_date

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
            self.authorization = ActivityLog.Authorization(activity_log_data.get("authorization", {}))
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
            self.properties = ActivityLog.Properties(activity_log_data.get("properties", {}))

    def __init__(self, data):
        self.schemaId = data.get("schemaId")
        self.status = data.get("data", {}).get("status")
        context_data = data.get("data", {}).get("context", {})

        self.activityLog = ActivityLog.ActivityLogDetails(context_data.get("activityLog", {}))
        self.resourceId = context_data.get("resourceId")
        self.resourceGroupName = context_data.get("resourceGroupName")
        self.resourceProviderName = context_data.get("resourceProviderName")
        self.status = context_data.get("status")
        self.subStatus = context_data.get("subStatus")
        self.subscriptionId = context_data.get("subscriptionId")
        self.submissionTimestamp = parse_date(context_data.get("submissionTimestamp"))
        self.resourceType = context_data.get("resourceType")
        self.properties = data.get("data", {}).get("properties")

    def extractAttributes(self):
        attributes = {}

        if self.properties is not None:
            properties_keys = self.properties.keys()
            for key in properties_keys:
                attributes[key] = self.properties[key]

        if self.subscriptionId:
            attributes.update({"subscriptionId": self.subscriptionId})

        return attributes