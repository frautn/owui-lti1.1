import base64
import hashlib
import hmac
import time
from urllib.parse import quote

from django.test import TestCase
from django.urls import reverse
from django.test.utils import override_settings


def _pct(value: str) -> str:
	return quote(str(value), safe='~')


def _normalized_params(payload: dict[str, str]) -> str:
	items = []
	for key, value in payload.items():
		if key == 'oauth_signature':
			continue
		items.append((_pct(key), _pct(value)))
	items.sort()
	return '&'.join(f'{k}={v}' for k, v in items)


def _make_signature(payload: dict[str, str], consumer_secret: str) -> str:
	base_url = 'http://testserver/lti/launch/'
	base_string = '&'.join(
		[
			_pct('POST'),
			_pct(base_url),
			_pct(_normalized_params(payload)),
		]
	)
	key = f'{_pct(consumer_secret)}&'
	digest = hmac.new(key.encode('utf-8'), base_string.encode('utf-8'), hashlib.sha1).digest()
	return base64.b64encode(digest).decode('utf-8')


class LTILaunchTests(TestCase):
	def _launch_payload(self) -> dict[str, str]:
		return {
			'lti_version': 'LTI-1p0',
			'lti_message_type': 'basic-lti-launch-request',
			'resource_link_id': 'res-1',
			'user_id': 'user-123',
			'roles': 'Learner',
			'context_id': 'ctx-42',
			'context_title': 'Course A',
			'oauth_consumer_key': 'moodle_key',
			'oauth_nonce': f'nonce-{time.time_ns()}',
			'oauth_timestamp': str(int(time.time())),
			'oauth_signature_method': 'HMAC-SHA1',
			'oauth_version': '1.0',
		}

	@override_settings(
		PYLTI_CONFIG={'consumers': {'moodle_key': {'secret': 'test-secret'}}}
	)
	def test_valid_lti_launch_redirects_to_chat(self):
		payload = self._launch_payload()
		payload['oauth_signature'] = _make_signature(
			payload,
			'test-secret',
		)

		response = self.client.post(reverse('lti_tool:launch'), data=payload)

		self.assertEqual(response.status_code, 302)
		self.assertEqual(response.url, reverse('lti_tool:chat'))

		session = self.client.session
		self.assertIn('lti_launch', session)
		self.assertEqual(session['lti_launch']['user_id'], 'user-123')

	@override_settings(
		PYLTI_CONFIG={'consumers': {'moodle_key': {'secret': 'test-secret'}}}
	)
	def test_invalid_signature_is_rejected(self):
		payload = self._launch_payload()
		payload['oauth_signature'] = 'invalid-signature'

		response = self.client.post(reverse('lti_tool:launch'), data=payload)

		self.assertEqual(response.status_code, 400)
		self.assertContains(response, 'OAuth signature validation failed.', status_code=400)
