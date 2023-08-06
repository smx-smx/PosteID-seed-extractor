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


# globals
OTP_PERIOD = 120
OTP_DIGITS = 6

USERPIN = "123456"

    
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


class PosteID:
    APP_NAME = 'app-posteid-v3'

    def __init__(self) -> None:
        self.s = None
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


    def jwe_header(self, app_id: str = None) -> dict:
        header = {
            "alg": "RSA-OAEP-256",
            "enc": "A256CBC-HS512",
            "typ": "JWT",
            "cty": "JWE",
            "kid": app_id if app_id != None else self.server_key.thumbprint(),
        }

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


    def jwe_encode(self, header: dict, content: dict) -> str:
        # convert content
        content_json = json.dumps(content)
        content_bytes = content_json.encode('utf-8')

        # build_jwe
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

    def http_preregistration(self) -> Union[str, JWK]:
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
        jwe = self.jwe_encode(self.jwe_header(), content)

        r = self.post(url, data=jwe)
        response = self.jwe_decode(r.text)

        app_id = response['data']['app-uuid']
        otp_secret_key = response['data']['otpSecretKey']
        otp_generator = new_auth_otp(otp_secret_key)
        return app_id, otp_generator
    
    def http_app_activation(self):
        url = 'https://appregistry-posteid.mobile.poste.it/jod-app-registry/v2/activation'
        content = self.jwe_content('register')
        jwe = self.jwe_encode(self.jwe_header(self.app_id), content)
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

    def http_appcheck_2(self):
        url = 'https://sh2-web-posteid.poste.it/jod-secure-holder2-web/public/app/v1/checkRegisterApp'

        header = self.jwe_header(self.app_id)
        data = {
            'appRegisterID': self.app_register_id 
        }
        content = self.jwe_content('checkRegisterApp', data)
        jwe = self.jwe_encode(header, content)

        self.post(url, data=jwe)

    def http_login(self, username: str, password: str):
        url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

        header = self.jwe_header(self.app_id)
        data = {
            'authLevel': '0',
            'userid': username,
            'password': password
        }
        content = self.jwe_content('login', data=data)
        jwe = self.jwe_encode(header, content)
        
        self.get(url, headers=jwe_bearer(jwe))

    def http_get_login_challenge(self):
        url = 'https://posteid.poste.it/jod-securelogin-schema/native/v5/challenge'

        header = self.jwe_header(self.app_id)
        data = {}
        content = self.jwe_content('login', data=data)
        jwe = self.jwe_encode(header, content)

        return self.get(url, data=jwe).json()
    
    def http_get_authorize_challenge(self, transaction):
        url = 'https://posteid.poste.it/jod-login-schema/secureholder/v4/challenge'

        header = self.jwe_header(self.app_id)
        data = {
            'jti': transaction['jti'],
            'appRegisterID': self.app_register_id
        }
        content = self.jwe_content('login', data=data)
        jwe = self.jwe_encode(header, content)
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
        
        header = self.jwe_header(self.app_id)
        jwe = self.jwe_encode(header, content)
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
        
        header = self.jwe_header(self.app_id)
        jwe = self.jwe_encode(header, content)
        return self.post(url, data=jwe).json()

    def http_v5_handshake(self):
        challenge = self.http_get_login_challenge()
        return self.http_login_challenge_authorize(challenge)


    def http_list_authorizations(self):
        url = 'https://posteid.poste.it/jod-securelogin-schema/native/v5/list-transaction'

        header = self.jwe_header(self.app_id)
        content = self.jwe_content('login', data={})        
        jwe = self.jwe_encode(header, content)
        resp = self.post(url, headers=jwe_bearer(self.access_token), data=jwe).json()
        assert resp["status"] == "v4_success", 'request failed ({}, {})'.format(resp["status"], resp["reason"])
        return resp
    

    def http_send_sms(self, username: str):
        url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

        # build jwe
        header = self.jwe_header(self.app_id)
        data = {
            'authLevel': '3',
            'userid': username, 
            'password': rand_uuid()
        }
        content = self.jwe_content('login', data=data)
        
        jwe = self.jwe_encode(header, content)

        # make http request
        self.get(url, headers=jwe_bearer(jwe))

    def http_submit_sms(self, sms_otp: str) -> str:
        url = 'https://posteid.poste.it/jod-securelogin-schema/v4/xmobileauthjwt'

        header = self.jwe_header(self.app_id)
        data = {
            'authLevel': '2',
            'otp': sms_otp,
            'nonce': rand_uuid()
        }
        content = self.jwe_content('login', data=data)
        jwe  = self.jwe_encode(header, content)
    
        r = self.get(url, headers=jwe_bearer(jwe))

        response = self.jwe_decode(r.headers['X-RESULT'])
        sms_alt_token = response['data']['token']
        return sms_alt_token

    def http_register_app(self, sms_alt_token: str, poste_pin: str={}) -> Union[str, str]:
        url = 'https://sh2-web-posteid.poste.it/jod-secure-holder2-web/public/app/v1/registerApp'

        # build jwe
        header = self.jwe_header(self.app_id)
        data = {
            'idpAccessToken': '',
            'registerToken': sms_alt_token,
            'userPIN': poste_pin
        }
        content = self.jwe_content('registerApp', data=data)
        jwe = self.jwe_encode(header, content)

        response_encoded = self.post(url, data=jwe).json()

        response = response_encoded['command-result']
        response_content = self.jwe_decode(response)

        app_register_id = response_content['data']['appRegisterID']
        secret_app = response_content['data']['secretAPP']

        return app_register_id, secret_app

    
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
            

    def initialize(self, from_saved = False):
        self.s = Session()
        self.s.headers.update({
            'User-Agent': 'okhttp/3.12.1'
        })
        
        if from_saved:
            self.read_session()
        else:
            self.app_pubkey, self.app_privkey = generate_pairs()
            
            registration_code, self.server_key = self.http_preregistration()
            self.app_id, self.otp_generator = self.http_registration(registration_code)
            self.app_id_hashed = sha256b64enc(self.app_id)
            self.http_app_activation()
            self.http_get_config()
            self.http_appcheck_1()

        self.http_appcheck_2()

        token = self.http_v5_handshake()
        self.profile_token = token['profile_token']
        self.access_token = token['access_token']
        self.token_expires_in = token['expires_in']

    def read_session(self):
        with open('secret.json', 'r') as f:
            session = json.loads(f.read())
            self.app_id = session['app_id']
            self.app_id_hashed = sha256b64enc(self.app_id)
            self.app_register_id = session['app_register_id']
            self.app_secret = session['app_secret']

            self.server_key = JWK.from_json(session['server_key'])
            self.app_privkey = JWK.from_json(session['app_privkey'])
            self.app_pubkey = RSA.import_key(self.app_privkey.export_to_pem(False, None)).export_key(format='DER')
            self.otp_counter = session['otp_counter']
            self.otp_generator = new_auth_otp(session['otp_secret'])

            self.token_expires_in = session['token_expires_in']
            self.access_token = session['access_token']
            self.profile_token = session['profile_token']

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
                # v5 handshake
                'access_token': self.access_token,
                'profile_token': self.profile_token,
                'token_expires_in': self.token_expires_in
            }, indent=4))

    def register_app(self):
        # ask login info
        username = input('Type username: ')
        password = getpass('Type password: ')
        self.http_login(username, password)
        del password

        # handle sms
        self.http_send_sms(username)
        sms_otp = input('Type SMS otp: ')
        sms_alt_token = self.http_submit_sms(sms_otp)
        del sms_otp

        userpin = USERPIN
        self.app_register_id, self.app_secret = self.http_register_app(sms_alt_token, userpin)

    def extract_cmd(self, only_output: bool, show_string: bool):
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

def next_otp(generator: HOTP) -> Union[int, str]:
    global otp_counter
    otp_counter += 1

    return otp_counter, generator.at(otp_counter)


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

    # extract command 
    extract = option_parser.add_parser('extract', help='Extract OTP code')
    extract.add_argument('-o', '--only-output', action='store_true',
                         help='Only show the output on the screen (do not write output in the secret.txt file)')
    extract.add_argument('-s', '--show-string', action='store_true',
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
    lib.initialize(True)

    if args.option == 'extract':
        lib.extract_cmd(args.only_output, args.show_string)
    elif args.option == 'generate_qr':
        lib.generate_qr_cmd(args.seed)
    elif args.option == 'generate_code':
        lib.generate_code_cmd(args.seed, args.time)
    elif args.option == 'authorize':
        lib.process_authorizations()


if __name__ == '__main__':
    main()
