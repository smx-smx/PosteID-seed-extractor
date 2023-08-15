#!/usr/bin/env python

from typing import Union
from requests import Session
from jwcrypto.jwk import JWK
from jwcrypto.jwe import JWE
from Crypto.PublicKey import RSA

from datetime import datetime as Datetime, timedelta as Timedelta
from pyotp import HOTP, TOTP
from getpass import getpass

import uuid
import hashlib
import hmac
import base64
import json
import sys
import argparse
import qrcode
import logging
import os
import random
from androguard.core.bytecodes import apk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
import requests
import checkin_pb2
import gzip
import time
import traceback

'''
references:
    https://blog.vocabustudy.org/posts/decoding-the-firebase-remote-config-rest-api/
    https://github.com/nborrmann/gcmreverse/
    https://github.com/BRUHItsABunny/go-android-firebase
    https://github.com/microg/GmsCore
    https://github.com/MCMrARM/Google-Play-API
'''


# globals
OTP_PERIOD = 120
OTP_DIGITS = 6

USERPIN = "123456"
APK_PATH = 'posteitaliane.posteapp.appposteid_4.5.441.apk'

    
def jwe_bearer(content: str) -> dict:
    result = { 'Authorization': 'Bearer {}'.format(content) }
    return result

def wrap_pem(key: str) -> str:
    template = '-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----'
    pem_key = template.format(key).encode('utf-8')
    return pem_key

def rand_hashed_uuid() -> Union[str, str]:
    uuid = rand_uuid()
    result = sha256b64enc(uuid)
    return uuid, result


def b64enc_str(content: bytes) -> str:
    result_encoded = base64.b64encode(content)
    return result_encoded.decode('utf-8')


def rand_uuid() -> str:
    # uuid version 4 generates a random uuid
    return str(uuid.uuid4())

def rand_firebase_id() -> str:
    bytes = bytearray(os.urandom(17))
    bytes[0] = 0x70 + (bytes[0] % 0x10)
    return base64.urlsafe_b64encode(bytes)[:22].decode('utf-8')

def sha256b64enc(content: str) -> str:
    content_bytes = content.encode('utf-8')
    
    digest = hashlib.sha256()
    digest.update(content_bytes)
    hash_result = digest.digest()

    return b64enc_str(hash_result)

def generate_pairs() -> Union[str, JWK]:
    keypair = RSA.generate(2048)

    public = keypair.publickey().exportKey(format='DER')
    private = JWK.from_pem(keypair.exportKey())

    return public, private

def times() -> Union[int, int]:
    now = Datetime.utcnow()
    minute = Timedelta(seconds=60)

    start = int(now.timestamp())
    end = int((now + minute).timestamp())

    return start, end

def new_auth_otp(otp_key: str) -> HOTP:
    return HOTP(otp_key, digits=8)

def random_meid():
    meid = "35503104"
    for i in range(0, 6):
        meid += str(random.randint(0, 9))
    return meid

def random_macaddr():
    mac = "b407f9"
    for i in range(0, 6):
        mac += '{:x}'.format(random.randint(0, 15))
    return mac


class PosteID:
    APP_NAME = 'app-posteid-v3'

    def __init__(self) -> None:
        self.s = None
        self.s_firebase = None
        self.s_gcm = None
        self.app_register_id = None
        self.server_key = None
        self.pubkey = None
        self.app_pubkey = None
        self.app_privkey = None
        self.app_secret = None
        self.otp_generator = None
        self.otp_counter = 0
        self.app_id = None
        self.app_id_hashed = None

        self.profile_token = None
        self.access_token = None
        self.token_expires_in = None

        self.app_package = None
        self.app_version_name = None
        self.app_version_code = None
        self.app_target_sdk = None
        self.google_app_id = None
        self.google_api_key = None
        self.google_android_cert = None
        self.google_sender_id = None
        self.firebase_id = None
        self.firebase_auth_token = None
        self.firebase_refresh_token = None
        self.firebase_token_expiry = None
        self.gms_androidid = None
        self.gms_security_token = None
        self.gms_notification_token = None

        self.username = None
        self.password = None
        self.sms_otp = None
        self.sms_alt_token = None



    def jwe_header(self) -> dict:
        header = {
            "alg": "RSA-OAEP-256",
            "enc": "A256CBC-HS512",
            "typ": "JWT",
            "cty": "JWE"
        }
        if self.app_id is not None:
            header['kid'] = self.app_id

        return header
    

    def next_otp(self) -> Union[int, str]:
        self.otp_counter += 1
        return self.otp_counter, self.otp_generator.at(self.otp_counter)

    def build_header_xkey(self) -> dict:
        when, otp = self.next_otp()
        result = { 'X-KEY': '{}:{}:{}'.format(self.app_id, otp, when) }
        return result

    def jwe_content(self, sub: str, data: dict={}):
        start, end = times()
        content = {
            'iss': 'app-posteid-v3',
            'sub': sub,
            'jti': rand_uuid(),
            'exp': end,
            'nbf': start,
            'iat': start,
            'data': data
        }

        if self.otp_generator is not None:
            otp_when, otp_code = self.next_otp()
            content['otp-specs'] = self.jwe_otp(otp_when, otp_code)

        if self.app_id_hashed is not None:
            content['kid-sha256'] = self.app_id_hashed


        return content


    def jwe_encode(self, content: dict) -> str:
        # convert content
        content_json = json.dumps(content)
        content_bytes = content_json.encode('utf-8')

        header = self.jwe_header()
        jwe = JWE(protected=header, plaintext=content_bytes, recipient=self.server_key)
        serialized = jwe.serialize(True)
        return serialized



    
    def jwe_otp(self, when: int, otp: str) -> dict:
        otp_dict = {
            'movingFactor': when,
            'otp': otp,
            'type': 'HMAC-SHA1'
        }
        return otp_dict

    
    def jwe_decode(self, content: str) -> dict:
        jwe_message = JWE()
        jwe_message.deserialize(content, self.app_privkey)
        result = json.loads(jwe_message.payload)
        return result

    def get(self, url: str, **kwargs):
        r = self.s.get(url, **kwargs)
        assert r.status_code == 200, 'GET Request failed ({} != 200)'.format(r.status_code)
        return r
    
    def post(self, url: str, **kwargs):
        r = self.s.post(url, **kwargs)
        assert r.status_code == 200, 'POST Request failed ({} != 200)'.format(r.status_code)
        return r

    def http_registration_init(self) -> Union[str, JWK]:
        url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v2/registerInit'

        registration_code, registration_code_hashed = rand_hashed_uuid()
        content = {
            'appName': PosteID.APP_NAME,
            'initCodeChallenge': registration_code_hashed
        }

        resp = self.post(url, json=content).json()
        pubkey_hex = resp['pubServerKey']
        pubkey = JWK.from_pem(wrap_pem(pubkey_hex))
        return registration_code, pubkey

    def http_registration(self, registration_code: str):
        url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v2/register'
        data = {
            'initCodeVerifier': registration_code,
            'xdevice': '{}::Android:10.0:SM-G960F:4.2.10:false'.format('A'*10), 
            'pubAppKey': b64enc_str(self.app_pubkey)
        }

        content = self.jwe_content('register', data)
        jwe = self.jwe_encode(content)

        r = self.post(url, data=jwe)
        response = self.jwe_decode(r.text)

        app_id = response['data']['app-uuid']
        otp_secret_key = response['data']['otpSecretKey']
        otp_generator = new_auth_otp(otp_secret_key)
        return app_id, otp_generator
    
    def http_app_activation(self):
        url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v2/activation'
        content = self.jwe_content('register')
        jwe = self.jwe_encode(content)
        self.post(url, data=jwe)

    def build_useless_header_app(self) -> dict:
        result = {'header': {'clientid': None, 'requestid': None}, 'body': {}}
        return result

    def http_get_config(self):
        url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v1/appregistry/appconfig'
        xkey = self.build_header_xkey()
        body = self.build_useless_header_app()
        self.post(url, headers=xkey, json=body)
        
    def http_appcheck_1(self):
        url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v1/appregistry/appcheck'
        xkey = self.build_header_xkey()
        body = self.build_useless_header_app()
        self.post(url, headers=xkey, json=body)

    def http_check_register_app(self):
        url = 'https://sh2-web-posteid.poste.it/jod-secure-holder2-web/public/app/v1/checkRegisterApp'

        data = {
            'appRegisterID': self.app_register_id 
        }
        content = self.jwe_content('checkRegisterApp', data)
        jwe = self.jwe_encode(content)

        self.post(url, data=jwe)

    def http_login(self, username: str, password: str):
        url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

        data = {
            'authLevel': '0',
            'userid': username,
            'password': password
        }
        content = self.jwe_content('login', data=data)
        jwe = self.jwe_encode(content)
        
        self.get(url, headers=jwe_bearer(jwe))

    def http_get_login_challenge(self):
        url = 'https://posteid.poste.it/jod-securelogin-schema/native/v5/challenge'

        data = {}
        content = self.jwe_content('login', data=data)
        jwe = self.jwe_encode(content)

        return self.get(url, data=jwe).json()
    
    def http_get_authorize_challenge(self, transaction):
        url = 'https://posteid.poste.it/jod-login-schema/secureholder/v4/challenge'

        data = {
            'jti': transaction['jti'],
            'appRegisterID': self.app_register_id
        }
        content = self.jwe_content('login', data=data)
        jwe = self.jwe_encode(content)
        return self.post(url, data=jwe).json()

    def http_authorize_challenge_authorize(self, challenge):
        url = 'https://posteid.poste.it/jod-login-schema/secureholder/v4/az'
        userpin = USERPIN
        hmac_key = (self.app_secret + userpin + challenge['randK']).encode('utf-8')

        challenge_message = challenge['transaction-challenge'].encode('utf-8')
        digest = hmac.new(hmac_key, challenge_message, hashlib.sha256).digest()
        
        signature = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip("=")
        
        data = {
            'signature': {
                'jti': challenge['jti'],
                'signature': signature,
                'userpin': userpin,
                'authzTool': 'POSTEID'
            },
            'appRegisterID': self.app_register_id
        }

        content = self.jwe_content('login', data=data)
        
        jwe = self.jwe_encode(content)
        return self.post(url, data=jwe).json()

    def http_login_challenge_authorize(self, challenge):
        url = 'https://posteid.poste.it/jod-securelogin-schema/native/v5/az'

        userpin = USERPIN
        hmac_key = (self.app_secret + userpin + challenge['randK']).encode('utf-8')

        challenge_message = challenge['transaction-challenge'].encode('utf-8')
        digest = hmac.new(hmac_key, challenge_message, hashlib.sha256).digest()
        
        signature = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip("=")
        
        data = {
            'signature': {
                'jti': challenge['jti'],
                'signature': signature,
                'userpin': userpin,
                'authzTool': 'POSTEID'
            },
            'appRegisterID': self.app_register_id
        }

        content = self.jwe_content('login', data=data)
        
        jwe = self.jwe_encode(content)
        return self.post(url, data=jwe).json()

    def http_v5_handshake(self):
        challenge = self.http_get_login_challenge()
        return self.http_login_challenge_authorize(challenge)


    def http_list_authorizations(self):
        url = 'https://posteid.poste.it/jod-securelogin-schema/native/v5/list-transaction'

        content = self.jwe_content('login', data={})        
        jwe = self.jwe_encode(content)
        resp = self.post(url, headers=jwe_bearer(self.access_token), data=jwe).json()
        assert resp["status"] == "v4_success", 'request failed ({}, {})'.format(resp["status"], resp["reason"])
        return resp
    
    def http_google_installations(self):
        url = 'https://firebaseinstallations.googleapis.com/v1/projects/app-posteid/installations'
        data = {
            'appId': self.google_app_id,
            'authVersion': 'FIS_v2',
            'fid': self.firebase_id,
            'sdkVersion': 'a:16.3.4'
        }
        headers = {
            'x-goog-api-key': self.google_api_key,
            'X-Android-Package': self.app_package,
            'X-Android-Cert': self.google_android_cert,
        }
        resp = self.s_firebase.post(url, headers=headers, json=data)
        assert resp.status_code == 200, "firebase request failed: {}".format(resp.status_code)
        return resp.json()
    
    def http_google_checkin(self):
        url = 'https://android.clients.google.com/checkin'

        req = checkin_pb2.CheckinRequest()
        req.accountCookie.append("")
        req.androidId = 0
        req.checkin.build.bootloader = 'unknown'
        req.checkin.build.brand = 'samsung'
        req.checkin.build.clientId = 'android-google'
        req.checkin.build.device = 'aosp'
        req.checkin.build.fingerprint = 'google/android_x86_64/x86_64:7.1.2/N2G48C/N975FXXU1ASGO:/release-keys'
        req.checkin.build.hardware = 'android_x86_64'
        req.checkin.build.manufacturer = 'samsung'
        req.checkin.build.model = 'SM-N971N'
        req.checkin.build.otaInstalled = False
        req.checkin.build.product = 'SM-N971N'
        req.checkin.roaming = 'WIFI::'

        #req.checkin.build.radio = 'unknown'
        req.checkin.build.sdkVersion = 25
        req.checkin.build.time = 1596634461
        
        #req.checkin.cellOperator = 'unknown'
        
        ev = checkin_pb2.CheckinRequest.Checkin.Event()
        ev.tag = "event_log_start"
        ev.timeMs = int(time.time()) * 1000
        req.checkin.event.append(ev)
        
        req.checkin.lastCheckinMs = 0
        req.checkin.userNumber = 0

        req.deviceConfiguration.widthPixels = 1920
        req.deviceConfiguration.heightPixels = 1080
        req.deviceConfiguration.densityDpi = 240
        req.deviceConfiguration.touchScreen = 3 # finger
        req.deviceConfiguration.keyboardType = 2 # qwerty
        req.deviceConfiguration.navigation = 1 # nonav
        req.deviceConfiguration.screenLayout = 4 # xlarge
        req.deviceConfiguration.hasHardKeyboard = False
        req.deviceConfiguration.hasFiveWayNavigation = False
        req.deviceConfiguration.glEsVersion = 0x30000
        
        for lib in [
            "android.test.runner", "com.android.future.usb.accessory", "com.android.location.provider",
            "com.google.android.gms", "javax.obex", "org.apache.http.legacy",
        ]: req.deviceConfiguration.sharedLibrary.append(lib)

        for plat in ["x86", "armeabi-x7a", "armeabi"]:
            req.deviceConfiguration.nativePlatform.append(plat)

        for locale in ['it', 'it_IT', 'en', 'en_US']:
            req.deviceConfiguration.locale.append(locale)

        for feature in [
            "android.hardware.audio.output", "android.hardware.bluetooth",
            "android.hardware.camera", "android.hardware.camera.any",
            "android.hardware.camera.autofocus", "android.hardware.camera.flash",
            "android.hardware.camera.front", "android.hardware.ethernet",
            "android.hardware.faketouch", "android.hardware.location",
            "android.hardware.location.gps", "android.hardware.location.network",
            "android.hardware.microphone", "android.hardware.screen.landscape",
            "android.hardware.screen.portrait", "android.hardware.sensor.accelerometer",
            "android.hardware.sensor.compass", "android.hardware.sensor.gyroscope",
            "android.hardware.sensor.light", "android.hardware.sensor.proximity",
            "android.hardware.touchscreen", "android.hardware.touchscreen.multitouch",
            "android.hardware.touchscreen.multitouch.distinct",
            "android.hardware.touchscreen.multitouch.jazzhand",
            "android.hardware.usb.accessory", "android.hardware.usb.host",
            "android.hardware.wifi", "android.hardware.wifi.direct",
            "android.software.app_widgets", "android.software.backup",
            "android.software.connectionservice", "android.software.device_admin",
            "android.software.input_methods", "android.software.live_wallpaper",
            "android.software.managed_users", "android.software.print",
            "android.software.sip", "android.software.sip.voip",
            "android.software.voice_recognizers", "android.software.webview",
            "com.google.android.feature.GOOGLE_BUILD",
            "com.google.android.feature.GOOGLE_EXPERIENCE"
        ]: req.deviceConfiguration.availableFeature.append(feature)

        req.digest = '1-929a0dca0eee55513280171a8585da7dcd3700f8'
        req.locale = 'it_IT'
        req.macAddress.append(random_macaddr())
        req.macAddressType.append('wifi')
        req.otaCert.append('71Q6Rn2DDZl1zPDVaaeEHItd')
        req.meid = random_meid()
        
        req.serial = '00d133b1'
        req.timeZone = 'Europe/Rome'
        req.version = 3
        req.fragment = 0
        req.userSerialNumber = 0
        req.securityToken = 0
        req.loggingId = random.randint(0,10000000)
           
        headers = {
            'Content-Type': 'application/x-protobuffer',
            'Content-Encoding': 'gzip',
            'Accept-Encoding': 'gzip',
            'User-Agent': 'Android-Checkin/2.0 (vbox86p JLS36G); gzip'
        }

        data = req.SerializeToString()
        compressed = gzip.compress(data)
        resp = requests.post(url, headers=headers, data=compressed)
        
        data = checkin_pb2.CheckinResponse.FromString(resp.content)
        return data

    def http_google_registration(self):
        gms_ver = '232518023'
        url = 'https://android.apis.google.com/c2dm/register3'
        data = {
            'X-subtype': self.google_sender_id,
            'sender': self.google_sender_id,
            'X-app_ver': self.app_version_code,
            'X-osv': '25',
            'X-cliv': 'fiid-21.0.0',
            'X-gmsv': gms_ver,
            'X-appid': self.firebase_id,
            'X-scope': '*',
            'X-Goog-Firebase-Installations-Auth': self.firebase_auth_token,
            'X-gmp_app_id': self.google_app_id,
            #'X-firebase-app-name-hash': 'R1dAH9Ui7M-ynoznwBdw01tLxhI',
            #'X-firebase-app-name-hash': base64.b64encode(
            #    hashlib.sha1(self.app_package.encode()).digest()
            #).decode('utf-8').rstrip('='),
            'X-firebase-app-name-hash': 'R1dAH9Ui7M-ynoznwBdw01tLxhI',
            'X-app_ver_name': self.app_version_name,
            'app': self.app_package,
            'device': self.gms_androidid,
            'app_ver': self.app_version_code,
            'gcm_ver': gms_ver,
            'plat': '0',
            'cert': self.google_android_cert.lower(),
            'target_ver': self.app_target_sdk
        }
        headers = {
            'Authorization': f"AidLogin {self.gms_androidid}:{self.gms_security_token}",
            'app': self.app_package,
            'gcm_ver': gms_ver,
            'app_ver': self.app_version_code,
            'User-Agent': 'Android-GCM/1.5 (aosp N2G48C)',
            'content-type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip',
        }

        resp = requests.post(url, headers=headers, data=data)
        assert resp.status_code == 200, "Request failed: {}".format(resp.status_code)
        assert resp.text.startswith('token='), "Registration failed: {}".format(resp.text)
        
        (_, token) = resp.text.split('=')
        return token
        

    def http_send_sms(self, username: str):
        url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

        # build jwe
        data = {
            'authLevel': '3',
            'userid': username, 
            'password': rand_uuid()
        }
        content = self.jwe_content('login', data=data)
        
        jwe = self.jwe_encode(content)

        # make http request
        self.get(url, headers=jwe_bearer(jwe))

    def http_submit_sms(self, sms_otp: str) -> str:
        url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

        data = {
            'authLevel': '2',
            'otp': sms_otp,
            'nonce': rand_uuid()
        }
        content = self.jwe_content('login', data=data)
        jwe  = self.jwe_encode(content)
    
        r = self.get(url, headers=jwe_bearer(jwe))

        response = self.jwe_decode(r.headers['X-RESULT'])
        sms_alt_token = response['data']['token']
        return sms_alt_token

    def http_register_app(self, sms_alt_token: str, poste_pin: str={}) -> Union[str, str]:
        url = 'https://sh2-web-posteid.poste.it/jod-secure-holder2-web/public/app/v1/registerApp'

        # build jwe
        data = {
            'idpAccessToken': '',
            'registerToken': sms_alt_token,
            'userPIN': poste_pin
        }
        content = self.jwe_content('registerApp', data=data)
        jwe = self.jwe_encode(content)

        response_encoded = self.post(url, data=jwe).json()

        response = response_encoded['command-result']
        response_content = self.jwe_decode(response)

        app_register_id = response_content['data']['appRegisterID']
        secret_app = response_content['data']['secretAPP']

        return app_register_id, secret_app
    
    def http_update_notification_token(self, notification_token):
        url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v1/appregistry/updateNotificationToken'
        body = {
            'body': {
                'notificationToken': notification_token
            },
            'header': {}
        }
        xkey = self.build_header_xkey()
        resp = self.post(url, headers=xkey, json=body).json()

        resp_header = resp['header']
        resp_command_result = int(resp_header['command-result'])
        assert resp_command_result == 0, "Command failed: {}".format(resp_command_result)

    
    def process_authorizations(self):
        list = self.http_list_authorizations()
        transactions = list['transaction']
        pending = transactions["pending"]
        if len(pending) < 1: return
        for entry in pending:
            status = entry["status"]
            if status != "v4_pending": continue

            data = json.loads(entry["appdata"])
            description = data['transaction-description']
            service = description["service"]
            print(f"authorizing \"{service}\" ...")

            self.http_get_authorize_challenge(transaction=data)
            result = self.http_authorize_challenge_authorize(challenge=data)
            print(result)
            
    def read_apk_file(self):
        a = apk.APK(APK_PATH)

        signature = a.get_signature()
        cert = pkcs7.load_der_pkcs7_certificates(signature)[0]
        bytes = cert.public_bytes(encoding = serialization.Encoding.DER)
        
        cert = hashlib.sha1(bytes).digest().hex().upper()

        self.app_version_name = a.get_androidversion_name()
        self.app_version_code = a.get_androidversion_code()
        self.app_target_sdk = a.get_target_sdk_version()

        package = a.get_package()
        rsrc = a.get_android_resources()
        self.app_package = package
        self.google_sender_id = rsrc.get_string(package, 'gcm_defaultSenderId')[1]
        self.google_api_key = rsrc.get_string(package, 'google_api_key')[1]
        self.google_app_id = rsrc.get_string(package, 'google_app_id')[1]
        self.google_android_cert = cert        

    def initialize(self, hot_login = False):
        cold_login = not hot_login

        self.s = Session()

        self.s_firebase = Session()
        self.s_gcm = Session()

        extra_data = self.read_session()

        # set an optional proxy address (e.g. mitmproxy) for debugging
        proxy = extra_data.get('proxy', None)
        proxy_enable = extra_data.get('proxy_enable', proxy is not None)
        if proxy is not None and proxy_enable:
            self.s.proxies = {kind: proxy for kind in ("http", "https", "ftp")}
            self.s.verify = False


        if not self.google_api_key or not self.app_version_name:
            self.read_apk_file()

        self.s.headers.update({
            'User-Agent': 'okhttp/3.12.1'
        })
        self.s_firebase.headers.update({
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; SM-N971N Build/N2G48C)',
            'X-Android-Package': self.app_package,
            'X-Android-Cert': self.google_android_cert,
            'x-goog-api-key': self.google_api_key
        })
        self.s_gcm.headers.update({
            'User-Agent': 'Android-GCM/1.5 (aosp N2G48C)',
        })

        # generate firebase ID
        if self.firebase_id is None:
            self.firebase_id = rand_firebase_id()

        if self.gms_androidid is None or \
        self.gms_security_token is None or \
        self.firebase_auth_token is None or cold_login:
            # obtain gms device id and security token
            data = self.http_google_checkin()
            self.gms_androidid = data.androidId
            self.gms_security_token = data.securityToken
            
            # obtain firebase tokens
            token_data = self.http_google_installations()
            self.firebase_id = token_data['fid']
            # name = token_data['name']
            auth_token = token_data['authToken']
            self.firebase_auth_token = auth_token['token']
            self.firebase_token_expiry = auth_token['expiresIn']
            self.firebase_refresh_token = token_data['refreshToken']

            self.gms_notification_token = self.http_google_registration()

        if self.app_pubkey is None or self.app_privkey is None:
            self.app_pubkey, self.app_privkey = generate_pairs()

        if self.server_key is None or self.otp_generator is None:
            registration_code, self.server_key = self.http_registration_init()
            self.app_id, self.otp_generator = self.http_registration(registration_code)
            self.app_id_hashed = sha256b64enc(self.app_id)
            self.http_app_activation()

        self.http_get_config()
        self.http_update_notification_token(self.gms_notification_token)
        self.http_appcheck_1()
        self.http_check_register_app()

       
        if self.app_secret is not None and hot_login:
            token = self.http_v5_handshake()
            self.profile_token = token['profile_token']
            self.access_token = token['access_token']
            self.token_expires_in = token['expires_in']

        self.write_session()

    def read_session(self):
        with open('secret.json', 'r') as f:
            session = json.loads(f.read())
            self.app_id = session.get('app_id')
            if self.app_id is not None:
                self.app_id_hashed = sha256b64enc(self.app_id)
            
            self.app_register_id = session.get('app_register_id')
            self.app_secret = session.get('app_secret')
    
            server_key = session.get('server_key')
            if server_key is not None:
                self.server_key = JWK.from_json(server_key)
            
            app_privkey = session.get('app_privkey')
            if app_privkey is not None:
                self.app_privkey = JWK.from_json(app_privkey)
                self.app_pubkey = RSA.import_key(self.app_privkey.export_to_pem(False, None)).export_key(format='DER')
            
            self.otp_counter = session.get('otp_counter', 0)
            otp_secret = session.get('otp_secret')
            if otp_secret is not None:
                self.otp_generator = new_auth_otp(otp_secret)

            self.token_expires_in = session.get('token_expires_in')
            self.access_token = session.get('access_token')
            self.profile_token = session.get('profile_token')

            self.app_package = session.get('app_package')
            self.app_version_name = session.get('app_version_name')
            self.app_version_code = session.get('app_version_code')
            self.app_target_sdk = session.get('app_target_sdk')
            self.google_app_id = session.get('google_app_id')
            self.google_api_key = session.get('google_api_key')
            self.google_android_cert = session.get('google_android_cert')
            self.google_sender_id = session.get('google_sender_id')

            self.gms_androidid = session.get('gms_androidid')
            self.gms_security_token = session.get('gms_security_token')
            self.gms_notification_token = session.get('gms_notification_token')

            self.firebase_id = session.get('firebase_id')
            self.firebase_auth_token = session.get('firebase_auth_token')
            self.firebase_refresh_token = session.get('firebase_refresh_token')
            self.firebase_token_expiry = session.get('firebase_token_expiry')

            self.username = session.get('username')
            self.password = session.get('password')
            self.sms_otp = session.get('sms_otp')
            self.sms_alt_token = session.get('sms_alt_token')
            return session

    def write_session(self):
        with open('secret.json', 'w') as f:
            f.write(json.dumps({
                'now': int(Datetime.utcnow().timestamp()),
                'app_id': self.app_id,
                'app_register_id': self.app_register_id,
                'server_key': self.server_key.export(),
                'app_privkey': self.app_privkey.export(),
                'app_secret': self.app_secret,
                'otp_secret': self.otp_generator.secret,
                'otp_counter': self.otp_counter,
                # creds
                'username': self.username,
                'password': self.password,
                'sms_otp': self.sms_otp,
                'sms_alt_token': self.sms_alt_token,
                # v5 handshake
                'access_token': self.access_token,
                'profile_token': self.profile_token,
                'token_expires_in': self.token_expires_in,
                # gms
                'app_package': self.app_package,
                'app_version_code': self.app_version_code,
                'app_version_name': self.app_version_name,
                'app_target_sdk': self.app_target_sdk,
                'google_app_id': self.google_app_id,
                'google_api_key': self.google_api_key,
                'google_android_cert': self.google_android_cert,
                'google_sender_id': self.google_sender_id,
                'gms_androidid': self.gms_androidid,
                'gms_security_token': self.gms_security_token,
                'gms_notification_token': self.gms_notification_token,
                # firebase
                'firebase_id': self.firebase_id,
                'firebase_auth_token': self.firebase_auth_token,
                'firebase_refresh_token': self.firebase_refresh_token,
                'firebase_token_expiry': self.firebase_token_expiry
            }, indent=4))

    def register_app(self):
        # ask login info
        self.username = input('Type username: ')
        self.password = getpass('Type password: ')
        self.http_login(self.username, self.password)

        # handle sms
        self.http_send_sms(self.username)
        self.sms_otp = input('Type SMS otp: ')
        self.sms_alt_token = self.http_submit_sms(self.sms_otp)

        userpin = USERPIN
        self.app_register_id, self.app_secret = self.http_register_app(self.sms_alt_token, userpin)

    def setup_cmd(self, only_output: bool, show_string: bool):
        self.register_app()

        # write output
        if not only_output:
            write_secret(self.app_secret)
            self.write_session()

        # write qr or seed
        if show_string:
            print(self.app_secret)
        else:
            self.generate_qr_cmd(self.app_secret)


    def generate_qr_cmd(self, seed: str=None):
        seed = read_secret_or_fail(seed)
        seed = parse_otp_seed(seed)

        uri = 'otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}'
        qr_uri = uri.format('PosteID', 'username', seed, 'PosteID', 'SHA1', OTP_DIGITS, OTP_PERIOD)

        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(qr_uri)

        qr.print_ascii(invert=True)

    def generate_code_cmd(self, seed: str=None, time: int=None):
        seed = read_secret_or_fail(seed)
        seed = parse_otp_seed(seed)

        generator = TOTP(seed, digits=OTP_DIGITS, interval=OTP_PERIOD, digest=hashlib.sha1)

        if time == None:
            code = generator.now()
        else:
            code = generator.at(time)

        print('Your code is: {}'.format(code))


def jwe_otp(when: int, otp: str) -> dict:
    otp_dict = {
        'movingFactor': when,
        'otp': otp,
        'type': 'HMAC-SHA1'
    }
    return otp_dict

def build_useless_header_app() -> dict:
    result = {'header': {'clientid': None, 'requestid': None}, 'body': {}}
    return result

def jwe_decode(content: str, jwe_key: JWK) -> dict:
    jwe_message = JWE()
    jwe_message.deserialize(content, jwe_key)
    result = json.loads(jwe_message.payload)
    return result

def read_secret() -> str:
    try:
        with open('secret.txt', 'r') as f:
            return f.readline()
    except:
        return None

def read_secret_or_fail(seed: str = None) -> str:
    if seed == None:
        seed = read_secret()
        if seed == None:
            print('No seed provided')
            exit()
    return seed

def parse_otp_seed(seed: str) -> str:
    key = base64.b32encode(seed.encode('utf-8'))
    return key.decode('utf-8')

def write_secret(secret: str):
    with open('secret.txt', 'w') as f:
        f.write(secret)



# main
def main():
    logging.basicConfig(level=logging.DEBUG)

    # check python version
    if sys.version_info.major < 3 or (sys.version_info.major == 3 and sys.version_info.minor <= 6):
        print('Python 3.6 or higher is required')

    # argument parser
    parser = argparse.ArgumentParser(description='This is a tool to extract the OTP seed of PosteID app')
    option_parser = parser.add_subparsers(title='option', dest='option', required=True, 
                                          description='Action to be performed')

    # setup command 
    setup = option_parser.add_parser('setup', help='Login and extract OTP code')
    setup.add_argument('-o', '--only-output', action='store_true',
                         help='Only show the output on the screen (do not write output in the secret.txt file)')
    setup.add_argument('-s', '--show-string', action='store_true',
                         help='Print OTP seed as string instead of qr code')
    

    authorize = option_parser.add_parser('authorize', help='Authorize pending SPID requests')

    # generate qr
    qr = option_parser.add_parser('generate_qr', help='Generate importable qr code')
    qr.add_argument('-s', '--seed', type=str, help='The OTP seed')

    # generate code
    code = option_parser.add_parser('generate_code', help = 'Generate OTP code of a specific time')
    code.add_argument('-s', '--seed', type=str, help='The OTP seed')
    code.add_argument('-t', '--time', type=str, help='Generate OTP in a precise time (UnixEpoch time), default is now')

    # parse
    args = parser.parse_args()

    lib = PosteID()

    use_saved_data = True
    if args.option == 'setup':
        use_saved_data = False

    login_expired = False

    try:
        lib.initialize(hot_login=use_saved_data)
    except AssertionError:
        traceback.print_exc()
        if use_saved_data:
            login_expired = True

    if login_expired:
        print("-- session expired, performing cold login")
        lib.initialize(hot_login=False)

    if args.option == 'setup':
        lib.setup_cmd(args.only_output, args.show_string)
    elif args.option == 'generate_qr':
        lib.generate_qr_cmd(args.seed)
    elif args.option == 'generate_code':
        lib.generate_code_cmd(args.seed, args.time)
    elif args.option == 'authorize':
        lib.process_authorizations()


if __name__ == '__main__':
    main()
