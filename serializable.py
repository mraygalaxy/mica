#!/usr/bin/env python
# coding: utf-8

from Queue import Queue as Queue_Queue, Empty as Queue_Empty
from threading import Thread, Lock, current_thread, Timer, local as threading_local
from traceback import format_exc
from common import *
from sqlalchemy import MetaData, create_engine, Table, Integer, String, Column, Float, or_
from sqlalchemy.interfaces import PoolListener

def serial(func):
    def wrapper(self, *args, **kwargs):
        mverbose("Wrap on thread " + str(current_thread()))
        mverbose("Wrapping serializable function: " + func.__name__ + " " + self.__class__.__name__)
        result = self.serial.safe_execute(self, func, *args, **kwargs)
        mverbose("Finished Wrapping serializable function: " + func.__name__ + " " + self.__class__.__name__)
        return result
    return wrapper

class Serializable(object) :
    def __init__(self, yes_or_no) :
        self.yes_or_no = yes_or_no
        self.q = Queue_Queue()
        self.consumer = Thread(target = self.consume)
        self.consumer.daemon = True

    def start(self) :
        mverbose("Starting internal serializable consumer thread.")
        self.consumer.start()

    def stop(self) :
        self.consumer.join()

    def safe_execute_serial(self) :
        (stuff, rq) = (yield)
        (real_self, func, args, kwargs) = stuff

        mverbose("Executing " + func.__name__ + " on " + str(current_thread()))
        try :
            if real_self :
                resp = func(real_self, *args, **kwargs)
            else :
                resp = func(*args, **kwargs)
            rq.put((resp, False))
        except Exception, e :
            err = ""
            for line in format_exc().splitlines() :
                err += line + "\n"
            merr(err)
            rq.put((False, e))

        rq.task_done()

    def safe_execute(self, real_self, func, *args, **kwargs) :
        if self.yes_or_no :
            if real_self :
                mverbose("Serializing " + func.__name__ + " " + real_self.__class__.__name__)
            else :
                mverbose("Serializing " + func.__name__)

            rq = Queue_Queue()
            co = self.safe_execute_serial()
            co.next()
            self.q.put((co, (real_self, func, args, kwargs), rq))
            (resp, error) = rq.get()
        else :
            mverbose("NOT Serializing " + func.__name__ + " " + str(args) + " " + str(kwargs))
            try :
                if real_self :
                    resp = func(real_self, *args, **kwargs)
                else :
                    resp = func(*args, **kwargs)
                error = False
            except Exception, e :
                merr(str(e))
                err = ""
                for line in format_exc().splitlines() :
                    merr(line)
                resp = False
                error = e

        if error :
            raise error
        return resp

    def consume(self) :
        while True :
            while True :
                try :
                    (co, req, rq) = self.q.get(timeout=10000)
                    break
                except Queue_Empty :
                    pass
            try :
                co.send((req, rq))
            except StopIteration :
                self.q.task_done()
                continue

            self.q.task_done()
