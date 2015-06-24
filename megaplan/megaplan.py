# -*- coding: utf-8 -*-

"""Megaplan client module.

Provides a class that implements Megaplan authentication and request signing.
Only supports POST requests.  The complete API documentation is at:

http://wiki.megaplan.ru/API

To use a password:

    import megaplan
    c = megaplan.Client('xyz.megaplan.ru')
    c.authenticate(login, password)

To use tokens:

    import megaplan
    # access_id, secret_key = c.authenticate(login, password)
    c = megaplan.Client('xyz.megaplan.ru', access_id, secret_key)

To list actual tasks:

    res = c.request('BumsTaskApiV01/Task/list.api', { 'Status': 'actual' })
    for task in res['tasks']:
        print task

License: BSD.
"""

import base64
import hashlib
import hmac
import time
import urllib
import urllib2

import simplejson


class Request:
    def __init__(self, hostname, access_id, secret_key, uri, data=None):
        self.method = 'POST'
        self.proto = 'http'
        self.uri = hostname + '/' + uri
        self.access_id = access_id
        self.secret_key = secret_key
        self.content_type = 'application/x-www-form-urlencoded'
        self.date = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
        self.signature = None
        self.data = data

    def sign(self):
        text = '\n'.join([self.method, '', self.content_type, self.date, self.uri])
        self.signature = base64.b64encode(hmac.new(str(self.secret_key), text, hashlib.sha1).hexdigest())


    def send(self):
        url = self.proto + '://' + self.uri
        data = self.data and urllib.urlencode(self.data)

        req = urllib2.Request(url, data)
        req.add_header('Date', self.date)
        req.add_header('Accept', 'application/json')
        req.add_header('User-Agent', 'SdfApi_Request')
        if self.signature:
            req.add_header('X-Authorization', self.access_id + ':' + self.signature)

        res = urllib2.urlopen(req)
        data = simplejson.loads(res.read())
        if data['status']['code'] != 'ok':
            raise Exception(data['status']['message'])

        if 'data' in data:
            return data['data']
        if 'json' in data:
            return data['json']


class Client:
    def __init__(self, hostname, access_id=None, secret_key=None):
        self.hostname = hostname
        self.access_id = access_id
        self.secret_key = secret_key

    def authenticate(self, login, password):
        """Authenticates the client.

        The access_id and secret_key values are returned.  They can be stored
        and used later to create Client instances that don't need to log in."""
        data = self.request('BumsCommonApiV01/User/authorize.api',
                            {'Login': login, 'Password': hashlib.md5(password).hexdigest()}, signed=False)
        self.access_id = data['AccessId']
        self.secret_key = data['SecretKey']
        EmployeeId = data['EmployeeId']
        return self.access_id, self.secret_key, EmployeeId

    def request(self, uri, args=None, signed=True):
        """Sends a request, returns the data.

        Args should be a dictionary or None; uri must not begin with a slash
        (e.g., "BumsTaskApiV01/Task/list.api").  If an error happens, an
        exception occurs."""
        if (self.access_id is None or self.secret_key is None) and signed == True:
            raise Exception('Authenticate first.')
        req = Request(self.hostname, self.access_id, self.secret_key, uri, args)
        if signed:
            req.sign()
        return req.send()

    # SOME HELPER METHODS

    def get_actual_tasks(self):
        """Returns your active tasks as a list of dictionaries."""
        return self.request('BumsTaskApiV01/Task/list.api', {'Status': 'actual'})['tasks']

    def get_tasks_by_status(self, status=None):
        """Returns your active tasks as a list of dictionaries."""
        return self.request('BumsTaskApiV01/Task/list.api', {'Status': status})['tasks']

    def get_task_details(self, task_id):
        return self.request('BumsTaskApiV01/Task/card.api', {'Id': task_id})

    def get_task_comments(self, task_id):
        return self.request('BumsCommonApiV01/Comment/list.api', {'SubjectType': 'task', 'SubjectId': task_id})

    def set_reaction(self, token, message):
        """Sets reaction by token."""
        return self.request('SdfNotify/ReactionApi/do.api', {'Token': token, 'params[text]': message})

    def get_employee_card(self, employee_id):
        """Returns Employee card"""
        return self.request('BumsStaffApiV01/Employee/card.api', {'Id': employee_id})

    def get_employee_list(self):
        """Returns Employee card"""
        return self.request('BumsStaffApiV01/Employee/list.api', {})


__all__ = ['Client']
