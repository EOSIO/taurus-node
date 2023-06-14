#!/usr/bin/env python3

from testUtils import Utils
from TestHelper import TestHelper
from WalletMgr import WalletMgr
from rodeos_utils import RodeosCluster
from Cluster import Cluster
from TestHelper import AppArgs
import time
import os
import logging
import requests
import requests_unixsocket


###############################################################
# rodeos_plugin_wasmQL_http_timeout test
# 
#   This test verifies timeout for wasmQL http connection through TCP/IP and unix socket to rodeos. The scenario in this test
#   is such that a persistent http connection is made to rodeos with timeout period of 5 second. Then we make 10 queries with a 
#   delay of 2.5s between each query and the session must be alive as the connection was active within the timeout period. 
#   Then the connection is kept in idle for the timeout period and rodeos must close out this idle session. Once we make another query
#   to rodeos, request module must reset the dropped session and throws this action in its logs. Through this log, this test can verify that
#   rodeos already closed out the idle session and new persistent connection has to be made again.
###############################################################

Print=Utils.Print

extraArgs=AppArgs()
extraArgs.add_bool("--eos-vm-oc-enable", "Use OC for rodeos")
extraArgs.add_bool("--unix-socket", "Enable unix socket")

args=TestHelper.parse_args({"--dump-error-details","--keep-logs","-v","--leave-running","--clean-run"}, extraArgs)
enableOC=args.eos_vm_oc_enable
enableUnixSocket=args.unix_socket
Utils.Debug=args.v
killAll=args.clean_run
dumpErrorDetails=args.dump_error_details
dontKill=args.leave_running
killEosInstances=not dontKill
killWallet=not dontKill
keepLogs=args.keep_logs
timeout = 5000


class LogStream(object): # this class parse log outputs from request module
    def __init__(self):
        self.logs = []

    def write(self, str):
        if len(self.logs) > 0 and 'Resetting dropped connection' in self.logs[-1]: # Once persistence connection is closed
            self.logs[-1]+= str                                                    # request throws 'Resetting dropped connection' in logs
        else:
            self.logs.append(str)

    def flush(self):
        pass

    def getlastlog(self):
        if len(self.logs) > 0:
            return self.logs[-1]
        return 'No log record'


walletMgr=WalletMgr(True)
cluster=Cluster(walletd=True)
cluster.setWalletMgr(walletMgr)

TestHelper.printSystemInfo("BEGIN")
testSuccessful=False
def launch_cluster(unix_socket_option, eos_vm_oc_enable=False):
    cluster.killall(allInstances=args.clean_run)
    cluster.cleanup()

    OCArg = " --eos-vm-oc-enable " if eos_vm_oc_enable else " "

    if enableUnixSocket:
        listenArg = " --wql-unix-listen ./var/lib/node_01/rodeos1.sock "
    else:
        listenArg = " --wql-listen 127.0.0.1:8881 "
    timeoutArg = " --wql-idle-timeout {} ".format(timeout)
    assert cluster.launch(
        pnodes=1,
        prodCount=1,
        totalProducers=1,
        totalNodes=2, # 1 rodeos
        useBiosBootFile=False,
        loadSystemContract=False,
        extraNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis",
        specificExtraNodeosArgs={
            0: "--plugin eosio::net_api_plugin --wasm-runtime eos-vm-jit ",
            1: "--disable-replay-opts --plugin b1::rodeos_plugin --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg + listenArg + timeoutArg
        })


    socket_path=os.path.join(os.getcwd(), Utils.getNodeDataDir(1))
    maincwd=os.getcwd()
    Print("Testing cluster of rodeos node connecting through {}"\
        .format((lambda x: 'Unix Socket' if (x==True) else 'TCP')(unix_socket_option)))

    log_stream = LogStream()
    logging.basicConfig(stream=log_stream, level=logging.DEBUG, format="%(message)s")

    if unix_socket_option:
        s = requests_unixsocket.Session()  # Opening persistence connetion
        os.chdir(socket_path)
        for i in range(10):                # making 10 wasm queries to rodeos with a half timeout delay netween each query
            r = s.get('http+unix://rodeos1.sock/v1/chain/get_info')
            time.sleep(timeout // 2000)
            assert r.status_code == 200, "Http request was not successful" # Http request must be successful
            print(log_stream.getlastlog())
            assert 'Resetting dropped connection: localhost' not in log_stream.getlastlog() # Connection made with timeout period so connection must be alive
    else:
        s = requests.Session()
        for i in range(10):
            r = s.get('http://127.0.0.1:8881/v1/chain/get_info')
            time.sleep(timeout // 2000)
            assert r.status_code == 200, "Http request was not successful"
            print(log_stream.getlastlog())
            assert 'Resetting dropped connection: localhost' not in log_stream.getlastlog()

    time.sleep(timeout // 1000) # idle connection for timeout period and expect rodeos to close the http session
                                # should see a timeout warning in rodeos logs also
    if unix_socket_option:
        r = s.get('http+unix://rodeos1.sock/v1/chain/get_info')
        assert r.status_code == 200, "Http request was not successful" # Http request must be successful
        print(log_stream.getlastlog())
    else:
        r = s.get('http://127.0.0.1:8881/v1/chain/get_info')
        assert r.status_code == 200, "Http request was not successful" # Http request must be successful
        print(log_stream.getlastlog())
    assert 'Resetting dropped connection' in log_stream.getlastlog() # Rodeos have already closed out previous session due to timeout
                                                                     # so request module has to open up a new session and throws
                                                                     # Resetting dropped connection in its logs
    if os.getcwd() != maincwd:
        os.chdir(maincwd)

try:
    launch_cluster(enableUnixSocket, enableOC)
    testSuccessful=True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

errorCode = 0 if testSuccessful else 1
exit(errorCode)
