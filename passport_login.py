import requests
import logging
import lxml.html as ET
import re
import json
import time
import os
import pickle
from getpass import getpass

DEBUG_DUMP = False
SESSION_FILE = 'session.dat'
SECRETS_FILE = 'credentials.json'

logging.basicConfig(level=logging.DEBUG)

def load_session(s: requests.Session):
	if not os.path.exists(SESSION_FILE):
		return

	with open(SESSION_FILE, 'rb') as f:
		cookies = pickle.load(f)
		s.cookies.update(cookies)

def save_session(s: requests.Session):
	with open(SESSION_FILE, 'wb') as f:
		pickle.dump(s.cookies, f)

def read_credentials():
	if not os.path.exists(SECRETS_FILE):
		return None
	with open(SECRETS_FILE, 'r') as f:
		return json.loads(f.read())

def debug_dump(file:str, data: str):
	if not DEBUG_DUMP:
		return
	
	if not os.path.exists('debug'): os.mkdir('debug')
	
	file_path = os.path.join('debug', file)
	with open(file_path, 'w', encoding='utf-8') as f:
		f.write(data)

def main():
	s = requests.Session()
	load_session(s)

	s.headers.update({
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/116.0"
	})
	resp = s.get("https://www.passaportonline.poliziadistato.it/LogInAction.do?codop=loginCittadino")
	assert resp.status_code == 200, "request failed"

	data = {
		"codop": "logCittadinoSPID"
	}
	resp = s.post("https://www.passaportonline.poliziadistato.it/LogInAction.do", data=data)
	assert resp.status_code == 200, "request failed"

	debug_dump('debug_loginaction.html', resp.text)

	root = ET.fromstring(resp.text)

	'''
	extract IDPs list from script
	'''
	for script in root.xpath("//script"):
		code = script.text
		if code is None: continue
		if "var idps" not in code: continue
		match = re.search(r'var idps\s*=\s*(\[.*\]);', code)
		if match is None: continue
		idps_json = match.group(1)
		idps = json.loads(idps_json)
		break

	# get IDP URL
	poste_idp = list(filter(lambda x: "posteid.poste.it" in x['entity_id'], idps)).pop()	
	resp = s.get(poste_idp['url'])
	assert resp.status_code == 200, "request failed"
	
	secrets = read_credentials()
	if secrets is not None:
		username = secrets['username']
		password = secrets['password']
	else:
		username = input('username: ')
		password = getpass('password: ')

	'''
	Login request
	'''
	pps = '1920' + '1080' + '24' + '1720' + '880'
	data = {
		'username': username,
		'password': password,
		'pps': pps,
		'dep': '',
		'dop': '',
		'evp': '',
		'mid': ''
	}
	resp = s.post("https://posteid.poste.it/jod-login-schema/xloginbasic", data=data)
	assert resp.status_code == 200, "request failed"
	debug_dump('debug_xlogin.html', resp.text)

	'''
	Send push notification request
	'''
	resp = s.get("https://posteid.poste.it/jod-login-schema/secureholder/generatepush?_=" + str(int(time.time())))
	assert resp.status_code == 200, "request failed"
	debug_dump('debug_generatepush.json', resp.text)

	'''
	Wait for authorization from app
	'''
	ticket = resp.json()
	id = ticket['ID']
	while True:
		polling_data = {
			'ID': id
		}
		resp = s.post("https://posteid.poste.it/jod-login-schema/polling/v4/app", json=polling_data)
		assert resp.status_code == 200, "request failed"

		data = resp.json()

		status = data['status']
		if status == 'v4_pending':
			time.sleep(1)
			continue
		
		assert status == 'v4_signed', "login failed"
		challenge = data['signegChallenge']
		break

	
	'''
	Submit signed token
	'''
	xlogin_data = {
		'secureToken': '',
		'secureTokenv4': challenge,
		'signature': ''
	}
	resp = s.post('https://posteid.poste.it/jod-login-schema/xlogindis', data=xlogin_data)
	assert resp.status_code == 200, "request failed"
	debug_dump('debug_xlogindis.html', resp.text)

	'''
	Load and submit consent page
	'''
	resp = s.get("https://posteid.poste.it/jod-login-schema/consent")
	assert resp.status_code == 200, "request failed"
	debug_dump('debug_consent.html', resp.text)

	root = ET.fromstring(resp.text)
	consent_ls = root.xpath("//input[@name='consent_ls']")[0].get('value')
	consent_sc = root.xpath("//input[@name='consent_sc']")[0].get('value')
	consent_data = {
		'consent': '1',
		'consent_ls': consent_ls,
		'consent_sc': consent_sc
	}

	resp = s.post("https://posteid.poste.it/jod-login-schema/consent", data=consent_data)
	assert resp.status_code == 200, "request failed"
	debug_dump('debug_saml.html', resp.text)
	
	'''
	Handle SAML
	'''
	root = ET.fromstring(resp.text)
	action = root.xpath("//form")[0].get('action')
	SAMLResponse = root.xpath("//input[@name='SAMLResponse']")[0].get('value')
	RelayState = root.xpath("//input[@name='RelayState']")[0].get('value')

	saml_data = {
		'SAMLResponse': SAMLResponse,
		'RelayState': RelayState
	}
	resp = s.post(action, data=saml_data)
	debug_dump('debug_result.html', resp.text)

	save_session(s)
		

if __name__ == '__main__':
	main()