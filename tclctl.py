#!/usr/bin/python3

from functools import cache, partial
from hashlib import pbkdf2_hmac
from subprocess import run
from urllib import request
from random import random
from os import environ
from time import time
import argparse
import datetime
import base64
import enum
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


class SMSType(enum.IntEnum):
    """Corresponds to the JSON field of the same name"""

    READ = 0
    UNREAD = 1
    OUTBOX = 2
    DRAFT = 6  # unused, but ????


class SMSBox(enum.StrEnum):
    """For use with get_sms_list()"""

    INBOX = "inbox"
    OUTBOX = "send"
    DRAFTS = "draft"  # unused


def openssl(data, passphrase, function):
    """
    Shell out to openssl for (de)obfuscation of API calls.
    This should not be called directly; the encrypt() wrapper is cached.
    (This will result in the same ciphertext being sent multiple times, which would be undesirable
    when using real encryption, but there is no actual security here so it doesn't matter.)
    """
    return run(
        ["openssl", "aes-256-cbc", "-md", "md5", "-k", passphrase, function],
        input=data,
        capture_output=True,
        check=True,
    ).stdout


encrypt = cache(partial(openssl, function="-e"))
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


def get_sms_list(key: SMSBox):
    """Get all messages from the given 'box'"""
    with Session() as sesh:
        sms = sesh.api("GetSMSListByContactNum", key=key, Page=1)
        smslist = sms["SMSList"]
        for page in range(2, sms["TotalPageCount"] + 1):
            smslist += sesh.api("GetSMSListByContactNum", key=key, Page=page)["SMSList"]
        return smslist


def format_message(message):
    """Format a message for output"""
    # SMSTimezone is apparently always -28, and SMSTime is apparently always UTC-7
    # from testing, this seems to remain true regardless of the set timezone
    # (which has never been UTC-7)
    # therefore, SMSTimezone evidently represents the UTC offset in 15 minute increments
    # (...but why UTC-7????)
    # anyways, the uncorrected UTC-7 time is shown on the web portal
    # so this program is actually an improvement over the reference implementation >:)
    # also, outgoing messages have the correct (naive?) datetime because ????????
    outbox = message["SMSType"] == SMSType.OUTBOX
    timestamp = datetime.datetime.fromisoformat(message["SMSTime"])
    if not outbox:
        timestamp = (
            timestamp.replace(
                tzinfo=datetime.timezone(
                    datetime.timedelta(minutes=15 * message["SMSTimezone"])
                )
            )
            .astimezone()
            .replace(tzinfo=None)
        )
    smsid = message["SMSId"]
    label = "To" if outbox else "From"
    # don't know why this is a list, since sending to a group isn't supported
    sender = ", ".join(message["PhoneNumber"])
    content = message["SMSContent"]
    return f"[{smsid}] {label} {sender} at {timestamp}:\n{content}"


def command_fetch(outbox=False, no_mark_read=False, all_=False):
    """Entry point for the fetch command"""
    smslist = get_sms_list(SMSBox.OUTBOX if outbox else SMSBox.INBOX)

    if formatted := [
        format_message(message)
        for message in smslist
        if all_ or message["SMSType"] != SMSType.READ
    ]:
        print("\n--------------------------------\n".join(formatted))
    else:
        print("No messages found")

    if not no_mark_read:
        if unread := list(
            filter(lambda message: message["SMSType"] == SMSType.UNREAD, smslist)
        ):
            with Session() as sesh:
                for message in unread:
                    # mark message as read, returning only its content
                    # (which you already had if you have its ID...)
                    sesh.api("GetSingleSMS", SMSId=message["SMSId"])


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        prog="tclctl",
        description="Manage SMS functionality of the TCL Linkport IK511 5G dongle",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch_parser = subparsers.add_parser("fetch", help="Fetch SMS messages")
    fetch_parser.add_argument(
        "--outbox", action="store_true", help="Fetch messages from outbox"
    )

    inbox_group = fetch_parser.add_argument_group("Inbox options")
    inbox_group.add_argument(
        "--no-mark-read", action="store_true", help="Do not mark messages as read"
    )
    inbox_group.add_argument(
        "--all",
        dest="all_",
        action="store_true",
        help="Fetch all messages instead of only unread messages",
    )

    """
    send_parser = subparsers.add_parser("send", help="Send an SMS")
    send_target = send_parser.add_mutually_exclusive_group(required=True)
    send_target.add_argument(
        "--number", metavar="phone_number", help="Recipient phone number"
    )
    send_target.add_argument(
        "--reply", metavar="sms_id", type=int, help="SMS ID to reply to"
    )

    delete_parser = subparsers.add_parser("delete", help="Delete SMS messages")
    delete_parser.add_argument(
        "--yes", action="store_true", help="Skip confirmation prompt"
    )
    delete_parser.add_argument(
        "ids", nargs="+", type=int, metavar="id", help="SMS IDs to delete"
    )
    """

    args = parser.parse_args()

    if args.command == "fetch" and args.outbox and (args.no_mark_read or args.all_):
        parser.error(
            "--outbox cannot be used with inbox options (--no-mark-read/--all)"
        )

    {
        "fetch": command_fetch,
    }[
        args.command
    ](**{k: v for k, v in vars(args).items() if k != "command"})


if __name__ == "__main__":
    main()
