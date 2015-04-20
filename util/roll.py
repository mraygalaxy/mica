#!/usr/bin/env python

from threading import Thread, Lock, current_thread, Timer, local as threading_local
from random import random
from time import sleep

#vt = Thread(target=self.view_runner_sched)
#vt.daemon = True
#vt.start()

periods = {"days" : {}, "weeks" : {}, "months" : {}, "years" : {} }
multipliers = { "days" : 7, "weeks" : 4, "months" : 12, "years" : 1 }
# All the months are not the same.... not sure what to do about that
counts = { "days" : 1, "weeks" : 7, "months" : 30, "years" : 365 }

current_day = 0

def get_index(period_key, total) :
    return (int(total) / counts[period_key]) % multipliers[period_key]

def add_period(period_key, event) :
    period_index = get_index(period_key, event)

    if str(period_index) not in periods[period_key] :
        # This will be an append when we have more messages per day
        # but just get it right first
        periods[period_key][str(period_index)] = []

    periods[period_key][str(period_index)].append(event)
    print "Adding " + str(event) + " to index " + str(period_index) + " of type " + period_key + ": " + str(periods[period_key])

def roll_period(period_key, period_next_key) :
    if get_index(period_key, current_day) == 0 :
        for period_index in range(0, multipliers[period_key]) :
            if str(period_index) in periods[period_key] :
                for event in periods[period_key][str(period_index)] :
                    add_period(period_next_key, event)

        periods[period_key] = {}


def dump_period(period_key) :
    print "Last " + period_key + ": " + str(len(periods[period_key]))
    for period_index in range(0, multipliers[period_key]) :
        if str(period_index) in periods[period_key] :
            print "\t" + str(period_index) + ": " + str(len(periods[period_key][str(period_index)])) + ": " + str(periods[period_key][str(period_index)])

while True :
    print "Current day: " + str(current_day)
    sleep(1)
    if random() < 0.3 :
        add_period("days", str(current_day))

    roll_period("days", "weeks")
    roll_period("weeks", "months")
    roll_period("months", "years")
    
    dump_period("days")
    dump_period("weeks")
    dump_period("months")

    current_day += 1
