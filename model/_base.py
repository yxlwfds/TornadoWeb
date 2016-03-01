# -*- coding: utf-8 -*-

import uuid, time, hashlib, base64, config, jwt

from random import randint

from tornado.log import app_log
from tornado.gen import sleep, coroutine, Return
from tornado.escape import utf8, to_basestring, json_decode, json_encode

from util.struct import Ignore
from util.cache import MCache
from util.database import MySQLPool, safestr


class BaseModel():
    
    randint = staticmethod(randint)
    
    safestr = staticmethod(safestr)
    
    sleep = staticmethod(sleep)
    
    debug = staticmethod(app_log.debug)
    error = staticmethod(app_log.error)
    
    json_encode = staticmethod(json_encode)
    json_decode = staticmethod(json_decode)
    
    @staticmethod
    def Return(value=None):
        
        raise Return(value)
    
    @staticmethod
    def Break():
        
        raise Ignore()
    
    @staticmethod
    def timestamp():
        
        return int(time.time())
        
    @staticmethod
    def b64_encode(val):
        
        val = utf8(val)
        
        result = base64.b64encode(val)
        
        return to_basestring(result)
    
    @staticmethod
    def b64_decode(val):
        
        val = utf8(val)
        
        result = base64.b64decode(val)
        
        return to_basestring(result)
    
    @staticmethod
    def jwt_encode(val, key):
        
        result = jwt.encode(val, key)
        
        return to_basestring(result)
    
    @staticmethod
    def jwt_decode(val, key):
        
        val = utf8(val)
        
        return jwt.decode(val, key)
    
    @staticmethod
    def uuid1(node=None, clock_seq=None):
        
        return uuid.uuid1(node, clock_seq).hex
    
    @staticmethod
    def md5(val):
        
        val = utf8(val)
        
        return hashlib.md5(val).hexdigest()
    
    @staticmethod
    def sha1(val):
        
        val = utf8(val)
        
        return hashlib.sha1(val).hexdigest()
    
    @staticmethod
    def sha256(val):
        
        val = utf8(val)
        
        return hashlib.sha256(val).hexdigest()
    
    @staticmethod
    def sha512(val):
        
        val = utf8(val)
        
        return hashlib.sha512(val).hexdigest()
    
    def __init__(self):
        
        # 数据缓存
        self._mc = MCache()
        
        # 数据连接池
        self._dbm = MySQLPool().master()
        self._dbs = MySQLPool().slave()
    
    def __del__(self):
        
        # 数据缓存
        self._mc = None
        
        # 数据连接池
        self._dbm = None
        self._dbs = None
    
    def cache_key(self, *keys):
        
        return self._mc.key(*keys)
    
    @coroutine
    def get_cache(self, key):
        
        result = yield self._mc.get(key)
        
        self.Return(result)
    
    @coroutine
    def set_cache(self, key, val, time=0):
        
        if(time == 0):
            time = config.Static.RedisExpires
        
        result = yield self._mc.set(key, val, time)
        
        self.Return(result)
    
    @coroutine
    def del_cache(self, key):
        
        result = yield self._mc.delete(key)
        
        self.Return(result)

