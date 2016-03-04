# -*- coding: utf-8 -*-

import time, uuid

from io import BytesIO

from tornado.log import app_log
from tornado.gen import sleep, coroutine, Return
from tornado.web import RequestHandler
from tornado.escape import json_encode, json_decode
from tornado.concurrent import Future

from .cache import MCache
from .captcha import Captcha
from .database import safestr
from .metaclass import SubclassMetaclass

from model.m_rbac import RbacModel


SESSION_EXPIRE = 3600


class RequestBaseHandler(RequestHandler):
    
    # 消息检查器列表
    _checkers = []
    
    safestr = staticmethod(safestr)
    
    sleep = staticmethod(sleep)
    
    debug = staticmethod(app_log.debug)
    error = staticmethod(app_log.error)
    
    @classmethod
    def get_module_name(cls):
        
        if(hasattr(cls, r'_module_name')):
            return cls._request_module
        
        request_module = r'.'.join([cls.__module__, cls.__name__])
        
        setattr(cls, r'_module_name', request_module)
        
        return request_module
    
    def initialize(self):
        
        self._cache = MCache()
    
    @coroutine
    def prepare(self):
        
        self._parse_json_arguments()
        
        if(self._checkers):
            
            for checker in self._checkers:
                
                result = checker(self)
                
                if(isinstance(result, Future)):
                    result = yield result
                
                if(not result):
                    self._finished or self.finish()
                    break
    
    def redirect(self, url, permanent=False):
        
        if(not permanent and url.find(r'?') < 0):
            url = r'{0}?_r={1}'.format(url, time.time())
        
        return super().redirect(url, permanent)
    
    def get_argument(self, name, default=None, strip=True):
        
        result = super().get_argument(name, default, strip)
        
        if(result is None):
            result = self.get_json_argument(name, default)
        
        return result
    
    def set_cookie(self, name, value, domain=None, expires=None, path="/", expires_days=None, **kwargs):
        
        if(type(value) not in (str, bytes)):
            value = str(value)
        
        return super().set_cookie(name, value, domain, expires, path, expires_days, **kwargs)
    
    def get_secure_cookie(self, name, value=None, max_age_days=31, min_version=None):
        
        result = super().get_secure_cookie(name, value, max_age_days, min_version)
        
        if(isinstance(result, bytes)):
            result = result.decode(r'utf-8')
        
        return result
    
    def set_secure_cookie(self, name, value, expires_days=30, version=None, **kwargs):
        
        if(type(value) not in (str, bytes)):
            value = str(value)
        
        return super().set_secure_cookie(name, value, expires_days, version, **kwargs)
    
    def get_current_user(self):
        
        session = self.get_cookie(r'session')
        
        if(not session):
            
            session = uuid.uuid1().hex
            
            self.set_cookie(r'session', session)
            
        self.current_user = session
        
        return session
    
    def _parse_json_arguments(self):
        
        content_type = self.content_type
        
        if(content_type and content_type.find(r'application/json') >= 0):
            try:
                self.json_arguments = json_decode(self.request.body)
            except Exception as error:
                app_log.warning('Invalid application/json body: %s', error)
    
    def _generate_captcha(self, width, height, line_num, line_width, font_color, back_color):
        
        code = None
        image = None
        
        with BytesIO() as stream:
            
            image = Captcha(width, height, line_num, line_width, font_color, back_color, r'static/fonts/impact.ttf')
            image.save(stream)
            
            code = image.code
            image = stream.getvalue()
        
        return code, image
    
    @property
    def request_module(self):
    
        return r'.'.join([self.get_module_name(), self.method])
    
    @property
    def method(self):
    
        return self.request.method.lower()
    
    @property
    def version(self):
    
        return self.request.version.lower()
    
    @property
    def host(self):
        
        return self.request.host
    
    @property
    def path(self):
        
        return self.request.path
    
    @property
    def query(self):
        
        return self.request.query
    
    @property
    def body(self):
        
        return self.request.body
    
    @property
    def client_ip(self):
        
        return self.request.remote_ip
    
    @property
    def content_type(self):
        
        return self.request.headers.get(r'Content-Type', r'')
    
    @property
    def content_length(self):
        
        result = self.request.headers.get(r'Content-Length', r'')
        
        return int(result) if result.isdigit() else 0
    
    def get_header(self, name, default=None):
        
        """
        获取header数据
        """
        return self.request.headers.get(name, default)
    
    def get_arg_str(self, name, default=r''):
        """
        获取str型输入
        """
        result = self.get_argument(name, None, True)
        
        if(result is None):
            return default
        else:
            return safestr(result)
    
    def get_arg_int(self, name, default=0):
        """
        获取int型输入
        """
        result = self.get_argument(name, None, True)
        
        if(result is None):
            result = default
        else:
            try:
                result = int(result)
            except:
                result = default
        
        return result
    
    def get_arg_float(self, name, default=0.0):
        """
        获取float型输入
        """
        result = self.get_argument(name, None, True)
        
        if(result is None):
            result = default
        else:
            try:
                result = float(result)
            except:
                result = default
        
        return result
    
    def get_arg_json(self, name, default=None):
        """
        获取json型输入
        """
        result = self.get_argument(name, None, True)
        
        if(result is None):
            result = default
        else:
            try:
                result = json_decode(result)
            except:
                result = default
        
        return result
    
    def get_json_argument(self, name, default=None):
        
        if(hasattr(self, r'json_arguments')):
            return self.json_arguments.get(name, default)
        else:
            return default
    
    def get_all_arguments(self, default=None):
        """
        获取全部输入
        """
        kwargs = {}
        
        for key in self.request.arguments.keys():
            kwargs[key] = self.get_argument(key, default, True)
        
        return kwargs
    
    def no_cache(self):
        
        self.set_header(r'Cache-Control', r'no-cache')
    
    def write_json(self, chunk, status_code=200):
        """
        输出JSON类型
        """
        self.set_header(r'Cache-Control', r'no-cache')
        self.set_header(r'Content-Type', r'application/json')
        
        if(status_code != 200):
            self.set_status(status_code)
        
        return self.finish(json_encode(chunk))
    
    def write_png(self, chunk):
        """
        输出PNG类型
        """
        self.set_header(r'Cache-Control', r'no-cache')
        self.set_header(r'Content-Type', r'image/png')
        
        return self.finish(chunk)
    
    def generate_captcha(self, width, height, line_num=10, line_width=(1,3), font_color=(0,0,0), back_color=(255,255,255)):
        
        code, image = self._generate_captcha(width, height, line_num, line_width, font_color, back_color)
        
        if(code and image):
            
            ckey = self._cache.key(r'captcha', self.current_user)
            
            yield self._cache.set(ckey, code, SESSION_EXPIRE)
            
            self.write_png(image)
    
    def validate_captcha(self, code):
        
        ckey = self._cache.key(r'captcha', self.current_user)
        
        captcha_code = yield self._cache.get(ckey)
        
        return code == captcha_code


class RequestSessHandler(RequestBaseHandler):
    
    @coroutine
    def prepare(self):
        
        yield self._build_session()
        
        yield super().prepare()
    
    def on_finish(self):
        
        super().on_finish()
        
        self._flush_session()
    
    @coroutine
    def _build_session(self):
        
        self._session_data = {}
        
        self._session_flush = False
        
        ckey = self._cache.key(r'session', self.current_user)
        
        result = yield self._cache.get(ckey)
        
        if(result and isinstance(result, dict)):
            self._session_data = result
    
    @coroutine
    def _flush_session(self):
        
        flush, self._session_flush = self._session_flush, False
        
        ckey = self._cache.key(r'session', self.current_user)
        
        if(self._session_data):
            
            if(flush):
                yield self._cache.set(ckey, self._session_data, SESSION_EXPIRE)
            else:
                yield self._cache.touch(ckey, SESSION_EXPIRE)
                
        elif(flush):
            
            yield self._cache.delete(ckey)
    
    def has_session(self, key):
        
        return key in self._session_data
    
    def get_session(self, key, default=None):
        
        return self._session_data.get(key, default)
    
    def set_session(self, key, val):
        
        self._session_data[key] = val
        
        self._session_flush = True
    
    def del_session(self, key=None):
        
        if(key is None):
            
            self._session_data.clear()
            
        else:
            
            if(key in self._session_data):
                del self._session_data[key]
        
        self._session_flush = True
    
    def generate_captcha(self, width, height, line_num=10, line_width=(1,3), font_color=(0,0,0), back_color=(255,255,255)):
        
        code, image = self._generate_captcha(width, height, line_num, line_width, font_color, back_color)
        
        if(code and image):
            
            self.set_session(r'captcha', code)
            
            self.write_png(image)
    
    def validate_captcha(self, code):
        
        captcha_code = self.get_session(r'captcha')
        
        return code == captcha_code


class RequestRbacHandler(RequestSessHandler, metaclass=SubclassMetaclass):
    
    @classmethod
    def get_rbac_modules(self):
        
        if(hasattr(self, r'_subclasses')):
            return getattr(self, r'_subclasses')
        else:
            return None
    
    @coroutine
    def prepare(self):
        
        yield super().prepare()
        
        if(not self._finished):
            
            result = yield self.rbac_auth()
            
            if(not result):
                self.send_error(401)
    
    @coroutine
    def rbac_auth(self):
        
        role = self.rbac_role
        
        if(not role):
            raise Return(False)
        
        if(role == 0xffffffff):
            raise Return(True)
        
        module = self.request_module
        history = self.get_session(r'rbac_hist')
        
        if(history):
            
            if(module in history):
                raise Return(history.get(module))
        
        else:
            
            history = {}
        
        m_rbac = RbacModel()
        
        result = yield m_rbac.auth(role, self.get_module_name(), self.method)
        
        history[module] = result
        
        self.set_session(r'rbac_hist', history)
        
        raise Return(result)
    
    @property
    def rbac_role(self):
        
        return self.get_session(r'rbac_role')
    
    @rbac_role.setter
    def rbac_role(self, role):
        
        self.set_session(r'rbac_role', role)

