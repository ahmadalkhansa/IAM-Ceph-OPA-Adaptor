#!/usr/bin/env python3

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn
import argparse
from scimclient import Scimclient
import time
import json
import httpx
import requests
from threading import Thread

parser = argparse.ArgumentParser(
                    prog = 'SOA',
                    description = 'SOA exploits SCIM endpoint that is part of INDIGO IAM to authorize sub claim values')

parser.add_argument('-i', '--clientid', type=str)
parser.add_argument('-s', '--clientsecret', type=str)
parser.add_argument('-u', '--username', type=str)
parser.add_argument('-p', '--password', type=str)
parser.add_argument('-r', '--issurl', type=str)
parser.add_argument('-n', '--rgwuser', type=str)
parser.add_argument('-a', '--rgwpass', type=str)
parser.add_argument('-e', '--rgwend', type=str)
parser.add_argument('-f', '--refresh', type=str)
parser.add_argument('-o', '--opa', type=str)

args = parser.parse_args()

app = FastAPI()

#scimming = Scimclient(issurl=args.issurl, clientid=args.clientid, clientsecret=args.clientsecret)

app.scimming = Scimclient(issurl=args.issurl, clientid=args.clientid, clientsecret=args.clientsecret, refresh_token=args.refresh)

print(app.scimming.clientid)

def uploadOPA(endpoint, doc):
    requests.put(endpoint, data=json.dumps(doc), headers={'Content-Type': 'application/json'})

@app.get("/health")
def tokenize():
    return "safe and sound"


@app.get("/collect")
def initialize():
#import pdb;pdb.set_trace()
    wait_auth = app.scimming.device_code()
    print("authorize the device by visiting {} and using the code {}".format(wait_auth.json()['verification_uri'], wait_auth.json()['user_code']))
    response = 400
    while response == 400:
        dev2auth = app.scimming.device_token(devicecode=wait_auth.json()['device_code'])
        response = dev2auth.status_code
        time.sleep(1)
    app.scimming.access_token = dev2auth.json()['access_token']
    app.scimming.refresh_token = dev2auth.json()['refresh_token']


@app.get("/")
def root():
    if app.scimming.access_token == "" or not app.scimming.still_valid():
        print("access token expired, refreshing ....\n")
        refresh_response = app.scimming.refresh2token()
        app.scimming.access_token = refresh_response.json()['access_token']
        print("the access token is: \n"+app.scimming.access_token+"\n")
    docfopa = app.scimming.OPAvdoc(app.scimming.get_users())
    Thread(target=uploadOPA, args=(args.opa, docfopa, )).start()
    time.sleep(3)
    content = {"message": "data updates"}
    headers = {"X-IAM": "fill info"}
    return JSONResponse(content=content, headers=headers)
    

if __name__ == "__main__":
#    initialize()
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) #workers=1)

