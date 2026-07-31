from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Dict
from urllib.parse import quote, urlparse

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt


REQUIRED_LTI_FIELDS = (
	'lti_version',
	'lti_message_type',
	'resource_link_id',
	'user_id',
	'oauth_consumer_key',
	'oauth_nonce',
	'oauth_timestamp',
	'oauth_signature_method',
	'oauth_version',
	'oauth_signature',
)


def _oauth_percent_encode(value: str) -> str:
	return quote(str(value), safe='~')


def _normalized_params(params: Dict[str, str]) -> str:
	items = []
	for key, value in params.items():
		if key == 'oauth_signature':
			continue
		items.append((_oauth_percent_encode(key), _oauth_percent_encode(value)))
	items.sort()
	return '&'.join(f'{k}={v}' for k, v in items)


def _signature_base_string(request: HttpRequest, params: Dict[str, str]) -> str:
	scheme, host, path = _normalized_launch_url_parts(request)
	normalized_url = f'{scheme}://{host}{path}'
	method = request.method.upper()
	normalized_params = _normalized_params(params)
	return '&'.join(
		[
			_oauth_percent_encode(method),
			_oauth_percent_encode(normalized_url),
			_oauth_percent_encode(normalized_params),
		]
	)


def _normalized_launch_url_parts(request: HttpRequest) -> tuple[str, str, str]:
	external_launch_url = getattr(settings, 'LTI_EXTERNAL_LAUNCH_URL', '')
	if external_launch_url:
		parsed = urlparse(external_launch_url)
		scheme = (parsed.scheme or 'https').lower()
		host = parsed.netloc.lower()
		path = parsed.path or request.path
		return scheme, host, path

	trust_proxy_headers = getattr(settings, 'LTI_TRUST_PROXY_HEADERS', True)
	if trust_proxy_headers:
		forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO', '')
		if forwarded_proto:
			scheme = forwarded_proto.split(',')[0].strip().lower()
		else:
			scheme = 'https' if request.is_secure() else 'http'

		forwarded_host = request.META.get('HTTP_X_FORWARDED_HOST', '')
		if forwarded_host:
			host = forwarded_host.split(',')[0].strip().lower()
		else:
			host = request.get_host().lower()
	else:
		scheme = 'https' if request.is_secure() else 'http'
		host = request.get_host().lower()

	path = request.path
	return scheme, host, path


def _sign_hmac_sha1(base_string: str, consumer_secret: str) -> str:
	signing_key = f'{_oauth_percent_encode(consumer_secret)}&'
	digest = hmac.new(
		signing_key.encode('utf-8'),
		base_string.encode('utf-8'),
		hashlib.sha1,
	).digest()
	return base64.b64encode(digest).decode('utf-8')


def _validate_timestamp(timestamp: str) -> bool:
	try:
		ts = int(timestamp)
	except ValueError:
		return False
	return abs(int(time.time()) - ts) <= 60 * 60


def _validate_nonce(consumer_key: str, nonce: str, timestamp: str) -> bool:
	nonce_key = f'lti_nonce:{consumer_key}:{timestamp}:{nonce}'
	return cache.add(nonce_key, '1', timeout=60 * 60)


def _launch_validation_error(params: Dict[str, str]) -> str | None:
	for field in REQUIRED_LTI_FIELDS:
		if not params.get(field):
			return f'Missing LTI field: {field}'

	if params.get('lti_version') != 'LTI-1p0':
		return 'Only LTI 1.1 launch payloads (LTI-1p0) are supported.'

	if params.get('lti_message_type') != 'basic-lti-launch-request':
		return 'Unsupported LTI message type.'

	if params.get('oauth_signature_method') != 'HMAC-SHA1':
		return 'Unsupported OAuth signature method. Expected HMAC-SHA1.'

	if params.get('oauth_version') != '1.0':
		return 'Unsupported OAuth version. Expected 1.0.'

	if not _validate_timestamp(params['oauth_timestamp']):
		return 'Invalid OAuth timestamp.'

	consumer = settings.PYLTI_CONFIG.get('consumers', {}).get(params['oauth_consumer_key'])
	if not consumer:
		return 'Unknown OAuth consumer key.'

	return None


def _verify_signature(request: HttpRequest, params: Dict[str, str]) -> bool:
	consumer = settings.PYLTI_CONFIG.get('consumers', {}).get(params['oauth_consumer_key'])
	if not consumer:
		return False
	consumer_secret = consumer['secret']
	base_string = _signature_base_string(request, params)
	expected_signature = _sign_hmac_sha1(base_string, consumer_secret)
	return hmac.compare_digest(expected_signature, params['oauth_signature'])


@csrf_exempt
def launch(request: HttpRequest) -> HttpResponse:
	if request.method != 'POST':
		return HttpResponseBadRequest('LTI launch must be a POST request.')

	params = {k: v for k, v in request.POST.items()}
	validation_error = _launch_validation_error(params)
	if validation_error:
		return HttpResponseBadRequest(validation_error)

	if not _verify_signature(request, params):
		return HttpResponseBadRequest('OAuth signature validation failed.')

	if not _validate_nonce(
		params['oauth_consumer_key'], params['oauth_nonce'], params['oauth_timestamp']
	):
		return HttpResponseBadRequest('OAuth nonce already used.')

	request.session['lti_launch'] = {
		'consumer_key': params.get('oauth_consumer_key'),
		'user_id': params.get('user_id'),
		'roles': params.get('roles', ''),
		'context_id': params.get('context_id', ''),
		'context_title': params.get('context_title', ''),
		'resource_link_id': params.get('resource_link_id', ''),
		'lis_person_name_full': params.get('lis_person_name_full', ''),
		'lis_person_contact_email_primary': params.get('lis_person_contact_email_primary', ''),
		'launch_time': int(time.time()),
	}
	return redirect('lti_tool:chat')


def chat(request: HttpRequest) -> HttpResponse:
	launch_data = request.session.get('lti_launch')
	if not launch_data:
		return HttpResponseBadRequest('No active LTI launch session found.')

	context = {
		'openwebui_url': settings.OPENWEBUI_URL,
		'lti_user': launch_data,
	}
	return render(request, 'lti_tool/chat.html', context)


def health(request: HttpRequest) -> JsonResponse:
	return JsonResponse({'status': 'ok'})


def config_xml(request: HttpRequest) -> HttpResponse:
	launch_url = request.build_absolute_uri(reverse('lti_tool:launch'))
	tool_title = 'OpenWebUI Chat'
	xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<cartridge_basiclti_link
	xmlns="http://www.imsglobal.org/xsd/imslticc_v1p0"
	xmlns:blti="http://www.imsglobal.org/xsd/imsbasiclti_v1p0"
	xmlns:lticm="http://www.imsglobal.org/xsd/imslticm_v1p0"
	xmlns:lticp="http://www.imsglobal.org/xsd/imslticp_v1p0"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="
		http://www.imsglobal.org/xsd/imslticc_v1p0
		http://www.imsglobal.org/profile/cc/ccv1p3/ccv1p3_lti_v1p0.xsd
		http://www.imsglobal.org/xsd/imsbasiclti_v1p0
		http://www.imsglobal.org/profile/cc/ccv1p3/imsbasiclti_v1p0p1.xsd
		http://www.imsglobal.org/xsd/imslticm_v1p0
		http://www.imsglobal.org/profile/cc/ccv1p3/imslticm_v1p0.xsd
		http://www.imsglobal.org/xsd/imslticp_v1p0
		http://www.imsglobal.org/profile/cc/ccv1p3/imslticp_v1p0.xsd">
	<blti:title>{tool_title}</blti:title>
	<blti:description>OpenWebUI chat launched from Moodle using LTI 1.1.</blti:description>
	<blti:launch_url>{launch_url}</blti:launch_url>
	<blti:extensions platform="moodle.org">
		<lticm:property name="privacy_level">public</lticm:property>
	</blti:extensions>
</cartridge_basiclti_link>
'''
	return HttpResponse(xml, content_type='application/xml')
