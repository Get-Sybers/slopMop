#!/usr/bin/env python3
import json
import requests

GRAPH = "https://graph.microsoft.com/v1.0"
headers = {"Authorization": "Bearer " + open("token_20261015_090010.json").read()}
for user in ["alice@corp.example", "bob@corp.example"]:
    mail = requests.get("https://graph.microsoft.com/v1.0/users/" + user + "/messages?$top=500", headers=headers)
    chat = requests.get("https://graph.microsoft.com/v1.0/users/" + user + "/mailFolders/TeamsMessagesData/messages", headers=headers)
sites = requests.get("https://graph.microsoft.com/v1.0/sites?search=*", headers=headers)
drive = requests.get("https://graph.microsoft.com/v1.0/sites/root/drives", headers=headers)
with open("collect_20261015_092040.txt", "w") as out:
    json.dump(sites.json(), out)
