#!/usr/bin/env python3

import time
import os
import shutil
import signal
import subprocess

from testUtils import Utils
from TestHelper import TestHelper
from TestHelper import AppArgs

###############################################################
# rodeos_filter_contracts_test
#
# This test focuses on testing filter contract related arguments
# handling: filter-name, filter-wasm, stream-loggers, stream-rabbits,
# stream-rabbits-exchange. To avoid excessive testing time,
# we do not start producer.
#
###############################################################

rodeosDir = os.path.join(os.getcwd(), 'var/lib/rodeos')
stdErrFileName = os.path.join(rodeosDir, "stderr.out")
rodeosStderr = None
rodeosStdout = None

def stopRodeos():
    Utils.Print("stopping Rodeos")
    subprocess.call(("pkill -15 nodeos").split())
    if rodeosStdout:
        rodeosStdout.close()
    if rodeosStderr:
        rodeosStderr.close()
    time.sleep(1)

def startRodeos(args = []):
    Utils.Print("starting Rodeos")
    shutil.rmtree(rodeosDir, ignore_errors=True)
    os.makedirs(rodeosDir, exist_ok=True)
    rodeosStdout = open(os.path.join(rodeosDir, "stdout.out"), "w")
    rodeosStderr = open(stdErrFileName, "w")
    subprocess.Popen(["./programs/nodeos/nodeos",
                      "--plugin", "b1::rodeos_plugin",
                      "--data-dir", rodeosDir] + args,
                     stdout=rodeosStdout, stderr=rodeosStderr)

def stdErrorContains(text):
    found = False
    with open(stdErrFileName) as logFile:
        for line in logFile:
            if text in line:
                found = True
                break
    return found

def run_test(title = "", args=[], expectedLogs=[]):
    Utils.Print("Test:", title)

    startRodeos(args)
    time.sleep(9)
    stopRodeos()

    for log in expectedLogs:
        if not stdErrorContains(log):
            Utils.Print(f'"{log}" not found in the log file')
            exit(1)

TestHelper.printSystemInfo("BEGIN")

# No filter contracts, no streamers
run_test(title = '0 filter contracts, 0 streamers',
        expectedLogs = ['number of filter contracts: 0'])

# Legacy filter only
run_test(title = 'Legacy filter only',
        args = ['--filter-name', 'test.filter', '--filter-wasm', './tests/test_filter.wasm'],
        expectedLogs = ['number of filters: 1',])

# Legacy filter and streamer
os.environ['EOSIO_STREAM_RABBITS'] = 'amqp://rabbits0.com:::amqp://rabbits1.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE'] = 'amqp://exhange1.com:::amqp://exhange2.com'
run_test(title = 'Legacy filter and streamer environment variable',
        args = ['--filter-name', 'test.filter', '--filter-wasm', './tests/test_filter.wasm', '--plugin', 'b1::streamer_plugin'],
        expectedLogs = ['number of filters: 1',
                        'number of legacy streams: 4']
        )
os.unsetenv('EOSIO_STREAM_RABBITS')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE')

# 1 filter contract, 1 logger, 1 rabbit, 1 exchange on command line
run_test(title = '1 filter contract, 1 logger, 1 rabbit, 1 exchange on command line',
        args = ['--filter-name-0', 'test.filter', '--filter-wasm-0', './tests/test_filter.wasm', '--plugin', 'b1::streamer_plugin', '--stream-loggers-0',  'logger1', '--stream-rabbits-0', 'amqp://rabbits.com', '--stream-rabbits-exchange-0', 'amqp://exhange.com'],
        expectedLogs = ['number of filters: 1',
                        'streamer: 0, number of initialized streams: 3', # total numbers of loggers, rabbits, and exchanges
                        'streamer: 1, number of initialized streams: 0'] # nothing for streamer 1
        )

# 1 filter contract, 2 loggers
run_test(title = '1 filter contract, 2 loggers on command line',
        args = ['--filter-name-0', 'test.filter', '--filter-wasm-0', './tests/test_filter.wasm', '--plugin', 'b1::streamer_plugin', '--stream-loggers-0', 'logger0', '--stream-loggers-1', 'logger1'],
        expectedLogs = ['number of filters: 1',
                        'streamer: 0, number of initialized streams: 1',
                        'streamer: 1, number of initialized streams: 1']
        )

# 1 filter contract, 2 loggers, 2 rabbits, 1 exchange using ebvironemnt variables
os.environ['EOSIO_STREAM_RABBITS_0'] = 'amqp://rabbits0.com:::amqp://rabbits1.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_0'] = 'amqp://exhange1.com'
run_test(title = '1 filter contract, 2 loggers, 2 rabbits, 1 exchange using environemnt variables',
        args = ['--filter-name-0', 'test.filter', '--filter-wasm-0', './tests/test_filter.wasm', '--plugin', 'b1::streamer_plugin', '--stream-loggers-0', 'logger0_0:::logger0_1'],
        expectedLogs = ['number of filters: 1',
                        'streamer: 0, number of initialized streams: 5', # total numbers of loggers, rabbits, and exchanges
                        'streamer: 1, number of initialized streams: 0']
        )

os.unsetenv('EOSIO_STREAM_RABBITS_0')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_0')

three_filters = ['--filter-name-0', 'filterzero', '--filter-name-1', 'filterone', '--filter-name-2', 'filtertwo', '--filter-wasm-0', './tests/test_filter.wasm', '--filter-wasm-1', './tests/test_filter.wasm', '--filter-wasm-2', './tests/test_filter.wasm']

# 3 filter contracts and 3 sets of streamers on command line
run_test(title = '3 filter contracts and 3 sets of streamers on command line',
    args = three_filters + ['--plugin', 'b1::streamer_plugin', '--stream-loggers-0', 'logger0', '--stream-rabbits-0', 'amqp://rabbits.com', '--stream-rabbits-exchange-0', 'amqp://exhange.com', '--stream-loggers-1', 'logger11:::logger12', '--stream-rabbits-1', 'amqp://rabbits1.com', '--stream-rabbits-exchange-1', 'amqp://exhange1.com', '--stream-loggers-2', 'logger2', '--stream-rabbits-2','amqp://rabbits21.com:::amqp://rabbits22.com', '--stream-rabbits-exchange-2', 'amqp://exhange21.com:::amqp://exhange22.com'],
    expectedLogs = [ 'number of filters: 3',
                     'streamer: 0, number of initialized streams: 3',
                     'streamer: 1, number of initialized streams: 4',
                     'streamer: 2, number of initialized streams: 5',
                     'streamer: 3, number of initialized streams: 0']
    )

# 3 filter contracts and 3 sets of streamers using environment variables
os.environ['EOSIO_STREAM_RABBITS_0'] = 'amqp://rabbits01.com:::amqp://rabbits02.com:::amqp://rabbits03.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_0'] = 'amqp://exhange01.com:::amqp://exhange02.com:::amqp://exhange02.com'
os.environ['EOSIO_STREAM_RABBITS_1'] = 'amqp://rabbits12.com:::amqp://rabbits22.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_1'] = 'amqp://exhange1.com'
os.environ['EOSIO_STREAM_RABBITS_2'] = 'amqp://rabbits2.com'

run_test(title = '3 filter contracts and 3 sets of streamers using environment variables',
        args = three_filters + ['--plugin', 'b1::streamer_plugin', '--stream-loggers-0', 'logger0_0'],
        expectedLogs = [ 'number of filters: 3',
                        'streamer: 0, number of initialized streams: 7',
                        'streamer: 1, number of initialized streams: 3',
                        'streamer: 2, number of initialized streams: 1',
                        'streamer: 3, number of initialized streams: 0']
        )
os.unsetenv('EOSIO_STREAM_RABBITS_0')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_0')
os.unsetenv('EOSIO_STREAM_RABBITS_1')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_1')
os.unsetenv('EOSIO_STREAM_RABBITS_2')

# 3 filter contracts and 2 sets of streamers using environment variables
os.environ['EOSIO_STREAM_RABBITS_0'] = 'amqp://rabbits01.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_0'] = 'amqp://exhange01.com'
os.environ['EOSIO_STREAM_RABBITS_1'] = 'amqp://rabbits12.com:::amqp://rabbits22.com'

run_test(title = '3 filter contracts and 2 sets of streamers using environment variables',
        args = three_filters + ['--plugin', 'b1::streamer_plugin', '--stream-loggers-1', 'logger1_0'],
        expectedLogs = ['number of filters: 3',
                        'streamer: 0, number of initialized streams: 2',
                        'streamer: 1, number of initialized streams: 3',
                        'streamer: 2, number of initialized streams: 0',
                        'streamer: 3, number of initialized streams: 0']
        )
os.unsetenv('EOSIO_STREAM_RABBITS_0')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_0')
os.unsetenv('EOSIO_STREAM_RABBITS_1')

# 5 filter contracts and 5 sets of streamers using environment variables
# Simulate production
os.environ['EOSIO_STREAM_RABBITS_0'] = 'amqp://rabbits01.com:::amqp://rabbits02.com:::amqp://rabbits03.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_0'] = 'amqp://exhange01.com:::amqp://exhange02.com:::amqp://exhange02.com'
os.environ['EOSIO_STREAM_RABBITS_1'] = 'amqp://rabbits12.com:::amqp://rabbits22.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_1'] = 'amqp://exhange1.com'
os.environ['EOSIO_STREAM_RABBITS_2'] = 'amqp://rabbits2.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_2'] = 'amqp://exhange2.com'
os.environ['EOSIO_STREAM_RABBITS_3'] = 'amqp://rabbits12.com:::amqp://rabbits22.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_3'] = 'amqp://exhange1.com'
os.environ['EOSIO_STREAM_RABBITS_4'] = 'amqp://rabbits2.com'
os.environ['EOSIO_STREAM_RABBITS_EXCHANGE_4'] = 'amqp://exhange2.com'

five_filters = ['--filter-name-0', 'filterzero', '--filter-name-1', 'filterone', '--filter-name-2', 'filtertwo', '--filter-wasm-0', './tests/test_filter.wasm', '--filter-wasm-1', './tests/test_filter.wasm', '--filter-wasm-2', './tests/test_filter.wasm', '--filter-name-3', 'filterthree', '--filter-wasm-3', './tests/test_filter.wasm', '--filter-name-4', 'filterfour', '--filter-wasm-4', './tests/test_filter.wasm']

run_test(title = '5 filter contracts and 5 sets of streamers using environment variables',
        args = five_filters + ['--plugin', 'b1::streamer_plugin'],
        expectedLogs = [ 'number of filters: 5',
                        'streamer: 0, number of initialized streams: 6',
                        'streamer: 1, number of initialized streams: 3',
                        'streamer: 2, number of initialized streams: 2',
                        'streamer: 3, number of initialized streams: 3',
                        'streamer: 4, number of initialized streams: 2',
                        'streamer: 5, number of initialized streams: 0',]
        )
os.unsetenv('EOSIO_STREAM_RABBITS_0')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_0')
os.unsetenv('EOSIO_STREAM_RABBITS_1')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_1')
os.unsetenv('EOSIO_STREAM_RABBITS_2')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_2')
os.unsetenv('EOSIO_STREAM_RABBITS_3')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_3')
os.unsetenv('EOSIO_STREAM_RABBITS_4')
os.unsetenv('EOSIO_STREAM_RABBITS_EXCHANGE_4')

# filter name and wasm not matched
run_test(title = 'filter name and wasm not matched',
        args = ['--filter-name-0', 'filterzero', '--filter-wasm-1', './tests/test_filter.wasm'],
        expectedLogs = ['filter-name-0 and filter-wasm-0 must be used together']
        )

# mixed legacy and multi filter contracts
run_test(title = 'mixed legacy and multi filter contracts',
        args = ['--filter-name', 'filtername', '--filter-wasm', './tests/test_filter.wasm', '--filter-name-0', 'filterzero', '--filter-wasm-0', './tests/test_filter.wasm'],
        expectedLogs = ['legacy and multiple filter contracts cannot be mixed']
        )

# duplicate filter names
run_test(title = 'duplicate filter names',
        args = ['--filter-name-0', 'filterzero', '--filter-wasm-0', './tests/test_filter.wasm', '--filter-name-1', 'filterzero', '--filter-wasm-1', './tests/test_filter.wasm'],
        expectedLogs = ['Filter name filterzero used multiple times']
        )

# no filter exists for a streamer
os.environ['EOSIO_STREAM_RABBITS_1'] = 'amqp://rabbits1.com'
run_test(title = 'no filter exists for a streamer',
        args = ['--filter-name-0', 'filterzero', '--filter-wasm-0', './tests/test_filter.wasm', '--plugin', 'b1::streamer_plugin', '--stream-loggers-1', 'logger1_0'],
        expectedLogs = ['No filter contracts exist for streamers {1}']
        )
os.unsetenv('EOSIO_STREAM_RABBITS_1')

# mixed legacy and multi streamers environment variable
os.environ['EOSIO_STREAM_RABBITS_1'] = 'amqp://rabbits1.com'
run_test(title = 'mixed legacy and multi streamers environment variable',
        args = ['--stream-rabbits-exchange', 'amqp://exhange1.com', '--plugin', 'b1::streamer_plugin'],
        expectedLogs = ['stream-rabbits-1 cannot be mixed with stream-rabbits, stream-rabbits-exchange, or stream-loggers'])
os.unsetenv('EOSIO_STREAM_RABBITS_1')

Utils.Print("END")
exit(0)
