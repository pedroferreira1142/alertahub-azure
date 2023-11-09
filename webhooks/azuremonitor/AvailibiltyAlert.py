class AvailibiltyAlert:
    def __init__(self, payload):
        self.schemaId = payload["data"]["schemaId"]
        self.version = payload["data"]["version"]
        self.properties = payload["data"]["properties"]
        self.status = payload["data"]["status"]
        self.context = payload["data"]["context"]

        self.id = self.context["id"]
        self.name = self.context["name"]
        self.description = self.context["description"]
        self.conditionType = self.context["conditionType"]
        self.severity = self.context["severity"]

        self.windowSize = self.context["condition"]["windowSize"]
        self.metricName = self.context["condition"]["allOf"][0]["metricName"]
        self.operator = self.context["condition"]["allOf"][0]["operator"]
        self.threshold = self.context["condition"]["allOf"][0]["threshold"]
        self.timeAggregation = self.context["condition"]["allOf"][0]["timeAggregation"]
        self.metricValue = self.context["condition"]["allOf"][0]["metricValue"]
        self.webTestName = self.context["condition"]["allOf"][0]["webTestName"]
