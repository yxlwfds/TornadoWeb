# -*- coding: utf-8 -*-

import config

from tornado.gen import coroutine
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httputil import url_concat
from tornado.escape import utf8, json_decode

from util.decorator import singleton, catch_error

from ._base import BaseModel


@singleton
class BaiduMapClient(BaseModel):
    
    def __init__(self):
        
        self._api_url = r'http://api.map.baidu.com'
        self._api_key = config.Static.BaiduMapAK
    
    @coroutine
    def __query(self, url, **kwargs):
        
        kwargs[r'ak'] = self._api_key
        kwargs[r'output'] = r'json'
        
        url = url_concat(r''.join([self._api_url, url]), kwargs)
        
        self.debug(url)
        
        result = None
        
        with catch_error():
            
            client = AsyncHTTPClient()
            
            response = yield client.fetch(HTTPRequest(url))
            
            result = json_decode(utf8(response.body))
            
        self.Return(result)
    
    @coroutine
    def geocode(self, location):
        """
        地址解析
        """
        
        aip_url = r'/geocoder/v2/'
        
        params = {}
        
        style = type(location)
        
        if(style is str):
            params[r'address'] = location
        elif(style in (list,tuple,)):
            params[r'location'] = r','.join(str(val) for val in location)
        
        response = yield self.__query(aip_url, **params)
        
        self.Return(response)
    
    @coroutine
    def ip(self, location):
        """
        IP定位
        """
        
        aip_url = r'/location/ip'
        
        params = {r'ip':location, r'coor':r'bd09ll'}
        
        response = yield self.__query(aip_url, **params)
        
        self.Return(response)

