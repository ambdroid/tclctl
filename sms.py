#!/usr/bin/python3

from functools import cache, partial
from hashlib import pbkdf2_hmac
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


def openssl(data, passphrase, function):
    """Shell out to openssl for (de)obfuscation of API calls."""
    return run(
        ["openssl", "aes-256-cbc", "-md", "md5", "-k", passphrase, function],
        input=data,
        capture_output=True,
        check=True,
    ).stdout


encrypt = partial(openssl, function="-e")
decrypt = partial(openssl, function="-d")


def api(name, login_token=None, passphrase=PASSPHRASE, **kwargs):
    """
    Perform an API call.
    login_token and passphrase are used by Session for authentication when needed.
    kwargs are formatted as a JSON dict.
    """
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


class Session:
    """
    A short-lived context manager for making one or more authenticated API calls in sequence.
    If there will be a significant or unknown delay between calls, a new Session should be used
    in order to avoid having to keep track of heartbeats or however else the tokens expire.
    """

    def __init__(self):
        self.password = self.get_password()
        self.token = api("Login", UserName=USERNAME, Password=self.password)["token"]

    @staticmethod
    @cache
    def get_password():
        password = environ["TCL_PASSWORD"].encode()
        salt = api("GetDeviceSt")["Salt"].encode()
        return pbkdf2_hmac("sha512", password, salt, 1024, 64).hex()

    def api(self, name, **kwargs):
        return api(
            name,
            self.token,
            # it's like a hash, but self-inverse! now that's security.
            self.password[64:] + self.password[:64],
            **kwargs,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.api("Logout")
        return False


with Session() as sesh:
    sms = sesh.api("GetSMSListByContactNum", key="inbox", Page=1)
    smslist = sms["SMSList"]
    for page in range(2, sms["TotalPageCount"] + 1):
        smslist += sesh.api("GetSMSListByContactNum", key="inbox", Page=page)["SMSList"]
    print(json.dumps(smslist, indent=4))
    for message in smslist:
        if message["SMSType"] == 1:  # 1/0 = (un)read
            # mark message as read, returning only its content
            # (which you already had if you have its ID...)
            sesh.api("GetSingleSMS", SMSId=message["SMSId"])
