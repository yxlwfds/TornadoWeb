# -*- coding: utf-8 -*-

import config

from tornado.gen import coroutine
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httputil import url_concat
from tornado.escape import utf8, json_decode

from util.decorator import singleton, catch_error

from ._base import BaseModel


@singleton
class TuringClient(BaseModel):
    
    def __init__(self):
        
        self._api_url = r'http://www.tuling123.com/openapi/api'
        self._api_key = config.Static.TuringApiKey
    
    @coroutine
    def __query(self, url, **kwargs):
        
        kwargs[r'key'] = self._api_key
        
        url = url_concat(r''.join([self._api_url, url]), kwargs)
        
        self.debug(url)
        
        result = None
        
        with catch_error():
            
            client = AsyncHTTPClient()
            
            response = yield client.fetch(HTTPRequest(url))
            
            result = json_decode(utf8(response.body))
            
        self.Return(result)
    
    @coroutine
    def chat(self, userid, info):
        
        aip_url = r''
        
        params = {r'userid':userid, r'info':info}
        
        response = yield self.__query(aip_url, **params)
        
        if(r'text' in response):
            self.Return(response[r'text'])
        elif(r'code' in response):
            self.Return(r'error {0}'.format(response[r'code']))

