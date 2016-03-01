# -*- coding: utf-8 -*-

__all__ = [r'start', r'stop']


import random

from tornado.gen import engine, sleep, Return

from util.task import AsyncTasks


def start():

    tasks = AsyncTasks()
    
    tasks.addTimeout(10, demo)
    
    tasks.addSchedule(r'* * * * *', demo)
    
    tasks.addWorker(lambda : print(r'Thread worker run'))


def stop():

    tasks = AsyncTasks()
    
    tasks.removeAllSchedule()


@engine
def demo():
    
    flag = random.randint(10000, 99999)
    
    print(r'Async task (%s) start'%flag)
    
    yield sleep(10)
    
    print(r'Async task (%s) running'%flag)
    
    yield sleep(10)
    
    print(r'Async task (%s) end'%flag)

