import json

from alerta.models.alert import Alert
from alerta.webhooks import WebhookBase
from dateutil.parser import parse as parse_date
import re
from datetime import datetime
import logging
import os

from alerta.plugins import PluginBase
from pyzabbix import ZabbixAPI, ZabbixAPIException
from flask import current_app, g, jsonify, make_response, request

try:
    from alerta.plugins import app  # alerta >= 5.0
except ImportError:
    from alerta.app import app  # alerta < 5.0


LOG = logging.getLogger('alerta.plugins.zabbix')

DEFAULT_ZABBIX_API_URL = 'http://localhost:10080'

ZABBIX_API_URL = os.environ.get(
    'ZABBIX_API_URL') or app.config.get('ZABBIX_API_URL', None)
ZABBIX_USER = os.environ.get('ZABBIX_USER') or app.config['ZABBIX_USER']
ZABBIX_PASSWORD = os.environ.get(
    'ZABBIX_PASSWORD') or app.config['ZABBIX_PASSWORD']

# See https://www.zabbix.com/documentation/4.0/manual/api/reference/event/acknowledge

NO_ACTION = 0
ACTION_CLOSE = 1
ACTION_ACK = 2
ACTION_MSG = 4
ACTION_SEV = 8

class UpdateZabbixWebhook(WebhookBase):
   
    def incoming(self, query_string, payload):

        alert = Alert.find_by_id(payload['alertId'], customers=g.get('customers', None))
        eventId = alert.attributes.get('eventId', None)
        triggerId = alert.attributes.get('triggerId', None)
        

         # login to zabbix
        zabbix_api_url = ZABBIX_API_URL or alert.attributes.get('zabbixUrl', DEFAULT_ZABBIX_API_URL)
        self.zapi = ZabbixAPI(zabbix_api_url)
        self.zapi.login(ZABBIX_USER, ZABBIX_PASSWORD)

        LOG.debug('Zabbix: acknowledge (%s) event=%s, resource=%s (triggerId=%s, eventId=%s) ',
                  payload['status'], alert.event, alert.resource, triggerId, eventId)

        if payload['status'] == 'ack':
            try:
                r = self.zapi.event.get(objectids=triggerId, acknowledged=False, output='extend', sortfield='clock', sortorder='DESC', limit=10)
                event_ids = [e['eventid'] for e in r]
            except ZabbixAPIException:
                LOG.error(f"No eventids retrieved from Zabbix for {triggerId}")
                return

            LOG.debug('Zabbix: status=ack; triggerId %s => eventIds %s',triggerId, ','.join(event_ids))

            try:
                LOG.debug('Zabbix: ack all events for trigger...')
                r = self.zapi.event.acknowledge(eventids=event_ids, action=(
                    ACTION_ACK | ACTION_MSG), message='{}: {}'.format(payload['status'], text))
            except ZabbixAPIException:
                try:
                    LOG.debug('Zabbix: ack all failed, ack only the one event')
                    r = self.zapi.event.acknowledge(eventids=eventId, action=(
                        ACTION_ACK | ACTION_MSG), message='{}: {}'.format(payload['status'], text))
                except ZabbixAPIException as e:
                    raise RuntimeError('Zabbix: ERROR - %s', e)
            finally:
                self.zapi.do_request('user.logout')

            LOG.debug('Zabbix: event.acknowledge(ack) => %s', r)
            text = text + ' (acknowledged in Zabbix)'

        elif payload['status'] == 'closed':

            try:
                r = self.zapi.event.get(objectids=triggerId, output='extend', sortfield='clock', sortorder='DESC', limit=10)
                event_ids = [e['eventid'] for e in r]
            except ZabbixAPIException:
                LOG.error(
                    f"No eventids retrieved from Zabbix for {triggerId}")
                return

            LOG.debug('Zabbix: status=closed; triggerId %s => eventIds %s',triggerId, ','.join(event_ids))

            try:
                LOG.debug('Zabbix: close all events for trigger...')
                r = self.zapi.event.acknowledge(eventids=event_ids, action=(
                    ACTION_CLOSE | ACTION_MSG), message='{}: {}'.format(payload['status'], text))
            except ZabbixAPIException:
                try:
                    LOG.debug(
                        'Zabbix: ack all failed, close only the one event')
                    r = self.zapi.event.acknowledge(eventids=triggerId, action=(
                        ACTION_CLOSE | ACTION_MSG), message='{}: {}'.format(payload['status'], text))
                except ZabbixAPIException as e:
                    raise RuntimeError('Zabbix: ERROR - %s', e)
            finally:
                self.zapi.do_request('user.logout')

            LOG.debug('Zabbix: event.acknowledge(closed) => %s', r)
            text = text + ' (closed in Zabbix)'

        return alert, payload['status']
