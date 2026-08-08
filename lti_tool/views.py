from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import token
from urllib.parse import quote, urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt

import requests
from typing import List, Optional, Dict, Any


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


def _signature_debug_hint(request: HttpRequest, params: Dict[str, str]) -> str:
	"""Return a safe hint to diagnose launch URL mismatches without exposing secrets."""
	scheme, host, path = _normalized_launch_url_parts(request)
	normalized_url = f'{scheme}://{host}{path}'
	reference_tool_url = request.build_absolute_uri(request.path)

	base_hint = (
		f'Verification used normalized URL {normalized_url}. '
		f'Request URL was {reference_tool_url}. '
	)

	external_launch_url = getattr(settings, 'LTI_EXTERNAL_LAUNCH_URL', '').strip()
	if external_launch_url:
		base_hint += 'LTI_EXTERNAL_LAUNCH_URL is set. Ensure Moodle Tool URL exactly matches it (including scheme, host, port, path, trailing slash).'
	else:
		base_hint += 'Set LTI_EXTERNAL_LAUNCH_URL to the exact Moodle Tool URL to avoid proxy/path mismatches.'

	return base_hint


def _build_openwebui_auth_url() -> str:
	base = settings.OPENWEBUI_URL.rstrip('/')
	# OpenWebUI's explicit /auth page can surface the "trusted header" warning
	# even when the LTI bridge already established a valid session via the API.
	# Send the browser straight to the app root so the session cookie is used.
	return f'{base}/'


def _build_safe_local_fallback_url() -> str:
	# Keep fallback inside Django to avoid exposing OpenWebUI auth warnings.
	return '/django/lti/health/'


def _openwebui_signin_with_retry(
	email: str,
	name: str,
	role: str,
	attempts: int = 2,
	delay_seconds: float = 0.35,
) -> tuple[str | None, str | None]:
	last_error: str | None = None

	for attempt in range(attempts):
		token, error = _openwebui_signin(email, name, role)
		if token:
			return token, None

		last_error = error
		if attempt < attempts - 1:
			time.sleep(delay_seconds)

	return None, last_error


def _create_chat_with_retry(
	auth_token: str,
	models: list[str],
	attempts: int = 2,
	delay_seconds: float = 0.35,
) -> str | None:
	for attempt in range(attempts):
		chat_id = create_openwebui_chat(auth_token=auth_token, models=models)
		if chat_id:
			return chat_id

		if attempt < attempts - 1:
			time.sleep(delay_seconds)

	return None


def _derive_lti_identity(launch_data: dict) -> tuple[str, str]:
	email = (launch_data.get('lis_person_contact_email_primary') or '').strip().lower()
	if not email:
		user_id = (launch_data.get('user_id') or 'lti-user').strip().lower()
		email = f'{user_id}@lti.local'

	name = (launch_data.get('lis_person_name_full') or '').strip()
	if not name:
		name = launch_data.get('user_id') or 'LTI User'

	return email, name


def _openwebui_error_detail(exc: HTTPError) -> str:
	try:
		error_payload = json.loads(exc.read().decode('utf-8'))
		detail = error_payload.get('detail')
		if detail:
			return str(detail)
	except Exception:
		pass
	return f'HTTP {exc.code}'


def _openwebui_signin_request(endpoint: str, headers: dict[str, str], body: dict) -> tuple[str | None, str | None]:
	request_body = json.dumps(body).encode('utf-8')
	request = Request(endpoint, data=request_body, headers=headers, method='POST')

	try:
		with urlopen(request, timeout=8) as response:
			payload = json.loads(response.read().decode('utf-8'))
	except HTTPError as exc:
		return None, _openwebui_error_detail(exc)
	except URLError as exc:
		return None, f'OpenWebUI is unreachable: {exc.reason}'
	except Exception:
		return None, 'OpenWebUI sign-in failed due to an unexpected error.'

	token = payload.get('token')
	if not token:
		return None, 'OpenWebUI sign-in succeeded but no token was returned.'

	return token, None


def _openwebui_signin(email: str, name: str, role: str) -> tuple[str | None, str | None]:
	endpoint = f"{settings.OPENWEBUI_URL.rstrip('/')}/api/v1/auths/signin"
	trusted_email_header = getattr(settings, 'OPENWEBUI_TRUSTED_EMAIL_HEADER', '').strip()
	trusted_name_header = getattr(settings, 'OPENWEBUI_TRUSTED_NAME_HEADER', '').strip()
	trusted_role_header = getattr(settings, 'OPENWEBUI_TRUSTED_ROLE_HEADER', '').strip()
	autologin_password = getattr(settings, 'OPENWEBUI_AUTOLOGIN_PASSWORD', '')

	headers = {'Content-Type': 'application/json'}
	body = {
		'email': email,
		'password': autologin_password,
	}

	if trusted_email_header:
		headers[trusted_email_header] = email
		if trusted_name_header:
			headers[trusted_name_header] = name
		if trusted_role_header:
			headers[trusted_role_header] = role
	elif not autologin_password:
		return None, 'OpenWebUI auto-login is not configured (missing trusted header mode and fallback password).'

	token, error = _openwebui_signin_request(endpoint, headers, body)
	if token:
		return token, None

	# If trusted-header mode is configured but not active in OpenWebUI, try password fallback.
	if trusted_email_header and autologin_password and error and 'email or password' in error.lower():
		fallback_headers = {'Content-Type': 'application/json'}
		fallback_body = {'email': email, 'password': autologin_password}
		fallback_token, fallback_error = _openwebui_signin_request(
			endpoint,
			fallback_headers,
			fallback_body,
		)
		if fallback_token:
			return fallback_token, None
		if fallback_error:
			return None, f'OpenWebUI sign-in failed: {fallback_error}'

	if trusted_email_header and not autologin_password and error and 'email or password' in error.lower():
		return (
			None,
			'OpenWebUI trusted-header auth appears inactive. Enable trusted header auth in OpenWebUI '
			f'or set OPENWEBUI_AUTOLOGIN_PASSWORD. Original error: {error}',
		)

	if error:
		return None, f'OpenWebUI sign-in failed: {error}'

	return None, 'OpenWebUI sign-in failed for an unknown reason.'


def _can_set_openwebui_cookie(request: HttpRequest, openwebui_url: str) -> bool:
	request_host = request.get_host().split(':')[0].lower()
	parsed = urlparse(openwebui_url)
	openwebui_host = (parsed.hostname or '').lower()
	return bool(openwebui_host and openwebui_host == request_host)


@csrf_exempt
def launch(request: HttpRequest) -> HttpResponse:
	if request.method != 'POST':
		return HttpResponse(
			'This endpoint expects an LTI launch POST request from Moodle. Open the tool from Moodle to start it.',
			content_type='text/plain',
			status=200,
		)

	params = {k: v for k, v in request.POST.items()}
	validation_error = _launch_validation_error(params)
	if validation_error:
		return HttpResponse(f'Invalid LTI launch: {validation_error}', content_type='text/plain', status=200)

	if not _verify_signature(request, params):
		message = 'OAuth signature validation failed.'
		if getattr(settings, 'LTI_SIGNATURE_DEBUG', False):
			message = f'{message} {_signature_debug_hint(request, params)}'
		return HttpResponse(message, content_type='text/plain', status=200)

	if not _validate_nonce(
		params['oauth_consumer_key'], params['oauth_nonce'], params['oauth_timestamp']
	):
		return HttpResponse('OAuth nonce already used.', content_type='text/plain', status=200)

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


def create_openwebui_chat(
    auth_token: str,
    models: List[str],
    system_prompt: Optional[str] = None,
    title: str = "Course Assistant Chat",
    file_ids: Optional[List[str]] = None,
	) -> Optional[str]:
    """
    Creates a new chat session in Open WebUI with a pre-configured model,
    system prompt, and optional attached files/knowledge bases.

    Returns the created chat_id (str) or None if the request failed.
    """

    url = f"{settings.OPENWEBUI_URL.rstrip('/')}/api/v1/chats/new"
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }

    # Format file objects if any file IDs were provided
    files_payload = []
    if file_ids:
        files_payload = [{"id": f_id, "type": "file"} for f_id in file_ids]

    # Construct Open WebUI chat session payload
    payload = {
        "chat": {
            "title": title,
            "models": models,
            "system": system_prompt or "",
            "files": files_payload,
            "history": {
                "messages": {},
                "currentId": None,
            },
        }
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Open WebUI returns the new chat object including its 'id'
        return data.get("id")
    
    except requests.RequestException as e:
        # Log error in your Django logger
        print(f"Error creating Open WebUI chat: {e}")
        return None


def chat(request: HttpRequest) -> HttpResponse:

	launch_data = request.session.get('lti_launch')
	if not launch_data:
		return HttpResponse(
			'No active LTI launch session found. Please launch the tool from Moodle again.',
			content_type='text/plain',
			status=200,
		)

	# role = 'admin' if 'Instructor' in launch_data.get('roles', '') else 'user'
	role = 'user'
	email, name = _derive_lti_identity(launch_data)
	token, login_error = _openwebui_signin_with_retry(email, name, role)
	can_set_cookie = _can_set_openwebui_cookie(request, settings.OPENWEBUI_URL)

	if token and not can_set_cookie:
		login_error = (
			'OpenWebUI token was created, but browser cookie handoff is blocked because '
			'OPENWEBUI_URL uses a different host than this LTI app.'
		)

	chat_id = None

	# 	# Define course-specific parameters from LTI launch_data
	# 	course_title = launch_data.get('context_title', 'Course Chat')
	# 	system_prompt = f"You are an AI teaching assistant for the course '{course_title}'. Always end your response with 'Hooray!'."
        
    #     # Optional: IDs of uploaded files or knowledge bases in Open WebUI
	# 	attached_file_ids = []  # e.g., ["3fa85f64-5717-4562-b3fc-2c963f66afa6"]

    #     # Create the session via API
	# 	chat_id = create_openwebui_chat(
    #         auth_token=token,
    #         models=["UTNFRA"],  # Specify target model ID
    #         system_prompt=system_prompt,
    #         title=f"LTI Chat - {course_title}",
    #         file_ids=attached_file_ids,
    #     )

	if token:
		chat_id = _create_chat_with_retry(
			auth_token=token,
			models=["utnfra"],  # Specify target model ID
		)
		if not chat_id and not login_error:
			login_error = (
				'We could not open your chat session right now. '
				'Please relaunch the activity from Moodle.'
			)
	elif not login_error:
		login_error = (
			'Automatic sign-in could not be completed right now. '
			'Please relaunch the activity from Moodle.'
		)

    # Build iframe URL pointing directly to the generated chat ID
	if chat_id:
		iframe_url = f"{settings.OPENWEBUI_URL.rstrip('/')}/c/{chat_id}"
	else:
		iframe_url = _build_safe_local_fallback_url()

	context = {
		'openwebui_auth_url': iframe_url,
		'autologin_error': login_error,
		'lti_user': launch_data,
	}
	response = render(request, 'lti_tool/chat.html', context)

	if token and can_set_cookie:
		response.set_cookie(
			key='token',
			value=token,
			path='/',
			samesite='None',
			secure=True,
			httponly=False,
		)

	return response


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
