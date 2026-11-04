"""Offline-only hosted Qwen adapter simulations. No network requests are made."""
import json
import socket
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.providers import AlibabaQwenProvider, InferenceRequest


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status = payload, status
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, size=-1): return self.payload[:size]


def response_body(text='synthetic answer', usage=None, finish_reason='stop'):
    return json.dumps({'choices':[{'finish_reason':finish_reason,'message':{'content':text}}],
                       'usage':usage or {'prompt_tokens':7,'completion_tokens':3}, 'id':'fake-id'}).encode()


class HostedQwenSimulationTests(unittest.TestCase):
    def setUp(self):
        self.provider=AlibabaQwenProvider(base_url='https://ws.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',
            model='qwen-plus',region='ap-southeast-1',api_key='unit-test-only',
            allowed_hosts=('ws.ap-southeast-1.maas.aliyuncs.com',),timeout_seconds=2,max_output_tokens=32)
        self.request=InferenceRequest(({'role':'user','content':'synthetic test only'},),'qwen-plus',32,2,
                                      {'type':'object','properties':{},'additionalProperties':False})
        self.provider.authorize_once(self.request,self.provider.fingerprint(self.request))

    def invoke(self, mocked):
        with patch('urllib.request.urlopen',mocked):
            return self.provider.infer(self.request)

    def test_valid_response_and_usage_are_parsed(self):
        result=self.invoke(lambda *a,**k: FakeResponse(response_body('{"ok":true}')))
        self.assertEqual(result.status,'success'); self.assertEqual(result.structured,{'ok':True})
        self.assertEqual((result.input_tokens,result.output_tokens),(7,3))

    def test_invalid_json_missing_fields_and_unexpected_payload_fail_safely(self):
        for body in (response_body('not json'), json.dumps({'choices':[]}).encode(), b'{}'):
            provider=AlibabaQwenProvider(base_url='https://ws.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',model='qwen-plus',region='ap-southeast-1',api_key='test',allowed_hosts=('ws.ap-southeast-1.maas.aliyuncs.com',))
            provider.authorize_once(self.request,provider.fingerprint(self.request))
            with patch('urllib.request.urlopen',return_value=FakeResponse(body)):
                result=provider.infer(self.request)
            self.assertEqual(result.status,'failed')

    def test_truncated_choice_is_failure_without_retry(self):
        provider=AlibabaQwenProvider(base_url='https://ws.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',
            model='qwen-plus',region='ap-southeast-1',api_key='test',
            allowed_hosts=('ws.ap-southeast-1.maas.aliyuncs.com',))
        provider.authorize_once(self.request,provider.fingerprint(self.request))
        with patch('urllib.request.urlopen',return_value=FakeResponse(response_body('{"ok":',finish_reason='length'))) as network:
            result=provider.infer(self.request)
        self.assertEqual(result.status,'failed')
        self.assertEqual(result.error_category,'invalid_or_truncated_output')
        self.assertEqual(network.call_count,1)

    def test_timeout_http_401_403_and_rate_limit_no_retry(self):
        failures=(socket.timeout(), urllib.error.HTTPError('https://example.invalid',401,'unauthorized',{},None),
                  urllib.error.HTTPError('https://example.invalid',403,'forbidden',{},None),
                  urllib.error.HTTPError('https://example.invalid',429,'rate limited',{},None))
        for failure in failures:
            provider=AlibabaQwenProvider(base_url='https://ws.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',model='qwen-plus',region='ap-southeast-1',api_key='test',allowed_hosts=('ws.ap-southeast-1.maas.aliyuncs.com',))
            provider.authorize_once(self.request,provider.fingerprint(self.request))
            with patch('urllib.request.urlopen',side_effect=failure) as network:
                result=provider.infer(self.request)
            self.assertEqual(result.status,'failed')
            self.assertEqual(network.call_count,1)

    def test_exact_payload_is_single_use_and_modified_prompt_rejected(self):
        changed=InferenceRequest(({'role':'user','content':'changed'},),'qwen-plus',32,2,self.request.json_schema)
        with patch('urllib.request.urlopen') as network:
            with self.assertRaises(PermissionError): self.provider.infer(changed)
            self.assertEqual(network.call_count,0)
        with patch('urllib.request.urlopen',return_value=FakeResponse(response_body('{"ok":true}'))):
            self.assertEqual(self.provider.infer(self.request).status,'success')
        with patch('urllib.request.urlopen') as network:
            with self.assertRaises(PermissionError): self.provider.infer(self.request)
            self.assertEqual(network.call_count,0)

    def test_unexpected_transport_exception_is_contained(self):
        result=self.invoke(lambda *a,**k: (_ for _ in ()).throw(RuntimeError('simulated')))
        self.assertEqual(result.status,'failed')
        self.assertEqual(result.error_category,'unexpected_provider_response')

if __name__=='__main__': unittest.main()
