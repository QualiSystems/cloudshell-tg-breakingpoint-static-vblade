#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
import json
import ssl

requests.packages.urllib3.disable_warnings()
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager


class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1)


class BP_API(object):
    def __init__(self, ip, username, password, logger):
        self.ip = ip
        self.username = username
        self.password = password
        self.logger = logger
        self.session = requests.Session()
        self.session.mount("https://", MyAdapter())

    def login(self):
        """ Login to Breaking Point Chassis """

        service = "https://{ip}/api/v1/auth/session".format(ip=self.ip)
        jheaders = {"content-type": "application/json"}
        jdata = json.dumps({"username": self.username, "password": self.password})
        r = self.session.post(service, data=jdata, headers=jheaders, verify=False)
        if r.status_code == 200:
            self.logger.debug("User <{username}> logged in successfully".format(username=self.username))
        else:
            self.logger.error(r.status_code)
            self.logger.error(r.content)
            raise Exception("Login failed. Please, verify provided username and password")

    def logout(self):
        """ Logout from Breaking Point Chassis """

        service = "https://{ip}/api/v1/auth/session".format(ip=self.ip)
        r = self.session.delete(service, verify=False)
        if r.status_code == 204:
            self.logger.debug("User <{username}> logged out successfully".format(username=self.username))

    def get_modules(self):
        """  """

        service = "https://{ip}/api/v1/{username}/vmdeployment/controller".format(ip=self.ip, username=self.username)
        r = self.session.get(service, verify=False)
        if r.status_code == 200:
            return r.json()
