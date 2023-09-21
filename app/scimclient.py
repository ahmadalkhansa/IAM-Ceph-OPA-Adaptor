#!/usr/bin/env python3

import requests
import argparse
import json
import os
import time
import base64
import json
from datetime import datetime
from jsonmerge import merge

class Scimclient:
    def __init__(self, issurl, clientid, clientsecret, refresh_token=""):
        self.issurl = issurl
        self.clientid = clientid
        self.clientsecret = clientsecret
        self.access_token = ""
        self.refresh_token = refresh_token


    def device_code(self):
        """
        Request device code from IAM.
        """
        payload = {'scope': 'scim scim:read offline_access',
                   'client_id': self.clientid
                   }
        response = requests.post(self.issurl+'/devicecode',
                params=payload,
                auth=(self.clientid, self.clientsecret),
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                )
        return response

    def device_token(self, devicecode):
        """
        Use device code to retrieve token.
        """
        payload = {'device_code': devicecode,
               'audience': 'account',
               'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'}
        response = requests.post(self.issurl+'/token',
            params=payload,
            auth=(self.clientid, self.clientsecret),
            )
        return response

    def refresh2token(self):
        """
        Use Refresh token to request Access token
        """
        rpayload = {'scopes': 'scim scim:read',
                'grant_type': 'refresh_token',
                'audience': 'account',
                'refresh_token': self.refresh_token
                }
        rresponse = requests.post(self.issurl+'/token',
                params=rpayload,
                auth=(self.clientid, self.clientsecret)
                )
        return rresponse

    def merge_jsons(self, *jsons):
        """
        create a dictionary by merging json arguments
        """
        merged_dict = {}
        for json_ in jsons:
            merged_dict = merge(merged_dict, json_)
        return merged_dict

    def number_of_users(self):
        """
        Get total number of users within IAM
        """
        token = self.access_token
        issurl = self.issurl
        headers = {'Authorization': f'Bearer {token}'}
        params = {'count': 0}
        response = requests.get(issurl+'/scim/Users', headers=headers, params=params)
        return response.json()['totalResults']

    def get_users(self):
        """
        Collect json from all pages and merge using merge_jsons
        """
        token = self.access_token
        issurl = self.issurl
        headers = {'Authorization': f'Bearer {token}'}
        nusers = self.number_of_users()
        hundreds = nusers // 100 + 1
        pages = []
        for index in range(hundreds):
            start_index = index * 100 + 1
            params = {'startIndex': start_index}
            response = requests.get(issurl+'/scim/Users', headers=headers, params=params)
            pages.append(json.loads(response.text))
        return self.merge_jsons(pages)

    def iam_scim(self):
        """
        This can be used if there is not pagination.
        """
        iam_token = self.access_token
        issurl = self.issurl
        scim_users = requests.get(issurl+'/scim/Users',
                headers={'Authorization': 'Bearer'+iam_token})

        user_info = scim_users.json()
        return user_info

    def OPAvdoc(self, scim_output):
        """
        Create a json from collected json with only id, username and group .
        """
        user_info = scim_output[0]
        users = {}
        for i in user_info['Resources']:
            groupList = []
            try:
                for x in i['groups']:
                    groupList.append(x['display'])
            except:
                pass
            users[i['id']] = {'userName': i['userName'],
                    'groups': groupList
                    }
        return users

    def still_valid(self):
        """
        Check the validity of the access token
        """
        access_token = self.access_token
        claims_encoded = access_token.split('.')[1]
        claims_decoded = base64.b64decode(claims_encoded+"=======")
        claims = json.loads(claims_decoded)
        if claims["exp"] - 5 < int(time.time()):
            return False
        return True


