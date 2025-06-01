#!/usr/bin/python3

from hashlib import pbkdf2_hmac
from functools import partial
from subprocess import run
from urllib import request
from random import random
from os import environ
from time import time
import base64
import json

API = "http://192.168.0.1/jrd/webapi?name="
HEADERS = {
    # clearly a literal keysmash
    "_TclRequestVerificationKey": "KSDHSDFOGQ5WERYTUIQWERTYUISDFG1HJZXCVCXBN2GDSMNDHKVKFsVBNf",
    "Origin": "http://192.168.0.1",
    "Referer": "http://192.168.0.1/",
}
USERNAME = "dc13ibej?7"  # 'admin' through a custom(?) hash
PASSPHRASE = "TCT@MiFiRouter"

PASSWORD = environ["TCL_PASSWORD"].encode()


def openssl(data, passphrase, function):
    return run(
        ["openssl", "aes-256-cbc", "-md", "md5", "-k", passphrase, function],
        input=data,
        capture_output=True,
        check=True,
    ).stdout


encrypt = partial(openssl, function="-e")
decrypt = partial(openssl, function="-d")


def api(name, login_token=None, passphrase=PASSPHRASE, **kwargs):
    header = {"_TclRequestVerificationToken": login_token} if login_token else {}
    blob = base64.b64encode(encrypt(json.dumps(kwargs).encode(), passphrase)).decode()
    with request.urlopen(
        request.Request(
            API + name,
            data=json.dumps(
                {
                    "_": int(time()),
                    "id": f"{random() * 100:.1f}",
                    "jsonrpc": "2.0",
                    "method": name,
                    "params": blob,
                }
            ).encode(),
            headers=HEADERS | header,
        )
    ) as f:
        js = json.loads(f.read().decode())
        if error := js.get("error"):
            raise RuntimeError(error)
        return json.loads(decrypt(base64.b64decode(js["result"]), passphrase).decode())


salt = api("GetDeviceSt")["Salt"].encode()
password = pbkdf2_hmac("sha512", PASSWORD, salt, 1024, 64).hex()
token = api("Login", UserName=USERNAME, Password=password)["token"]
api_auth = partial(
    api,
    login_token=token,
    # it's like a hash, but self-inverse! now that's security.
    passphrase=password[64:] + password[:64],
)


sms = api_auth("GetSMSListByContactNum", key="inbox", Page=1)
smslist = sms["SMSList"]
for page in range(2, sms["TotalPageCount"] + 1):
    smslist += api_auth("GetSMSListByContactNum", key="inbox", Page=page)["SMSList"]
print(json.dumps(smslist, indent=4))
for message in smslist:
    if message["SMSType"] == 1:  # 1/0 = (un)read
        # mark message as read, returning only its content
        # (which you already had if you have its ID...)
        api_auth("GetSingleSMS", SMSId=message["SMSId"])


api_auth("Logout")
