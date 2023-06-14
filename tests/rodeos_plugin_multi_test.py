#!/usr/bin/env python3

from testUtils import Utils
from TestHelper import TestHelper
from Cluster import Cluster
from rodeos_utils import RodeosUtils
from WalletMgr import WalletMgr
from TestHelper import AppArgs

import time
import subprocess
###############################################################
# rodeos_plugin_multi_test
# 
#   This test verifies launch of a cluster of several rodeos nodes in idle and under load states, rodeos receives
#   blocks from producer. Rodeos connection are either Unix socket or TCP/IP.
#
###############################################################

Print=Utils.Print

extraArgs=AppArgs()
extraArgs.add_bool("--eos-vm-oc-enable", "Use OC for rodeos")
extraArgs.add_bool("--load-test-enable", "Enable load test")

args=TestHelper.parse_args({"--dump-error-details","--keep-logs","-v","--leave-running","--clean-run"}, extraArgs)
enableOC=args.eos_vm_oc_enable
enableLoadTest=args.load_test_enable
Utils.Debug=args.v
killAll=args.clean_run
dumpErrorDetails=args.dump_error_details
dontKill=args.leave_running
killEosInstances=not dontKill
killWallet=not dontKill
keepLogs=args.keep_logs


TestHelper.printSystemInfo("BEGIN")
testSuccessful=False
def launch_cluster(num_rodeos, unix_socket_option, eos_vm_oc_enable=False):
    global testSuccessful
    testSuccessful=False
    walletMgr=WalletMgr(True)
    cluster=Cluster(walletd=True)
    cluster.setWalletMgr(walletMgr)

    try:
        cluster.killall(allInstances=killAll)
        cluster.cleanup()

        OCArg = " --eos-vm-oc-enable " if eos_vm_oc_enable else " "

        if unix_socket_option:
            listenArg1 = " --wql-unix-listen ./var/lib/node_01/rodeos0.sock --wql-listen disable "
            listenArg2 = " --wql-unix-listen ./var/lib/node_02/rodeos1.sock --wql-listen disable "
            listenArg3 = " --wql-unix-listen ./var/lib/node_03/rodeos2.sock --wql-listen disable "
        else:
            listenArg1 = " --wql-listen 127.0.0.1:8880 "
            listenArg2 = " --wql-listen 127.0.0.1:8881 "
            listenArg3 = " --wql-listen 127.0.0.1:8882 "

        specificExtraNodeosArgs=None
        if num_rodeos == 2:
            specificExtraNodeosArgs={
                0: "--plugin eosio::net_api_plugin --wasm-runtime eos-vm-jit --chain-state-db-size-mb=131072 --plugin eosio::txn_test_gen_plugin ",
                1: "--chain-state-db-size-mb=131072 --disable-replay-opts --plugin b1::rodeos_plugin --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg + listenArg1,
                2: "--chain-state-db-size-mb=131072 --disable-replay-opts --plugin b1::rodeos_plugin --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg + listenArg2
            }
        elif num_rodeos == 3:
            specificExtraNodeosArgs={
                0: "--chain-state-db-size-mb=131072 --plugin eosio::txn_test_gen_plugin --plugin eosio::net_api_plugin --wasm-runtime eos-vm-jit ",
                1: "--chain-state-db-size-mb=131072 --disable-replay-opts --plugin b1::rodeos_plugin --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg + listenArg1,
                2: "--chain-state-db-size-mb=131072 --disable-replay-opts --plugin b1::rodeos_plugin --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg + listenArg2,
                3: "--chain-state-db-size-mb=131072 --disable-replay-opts --plugin b1::rodeos_plugin --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg + listenArg3
            }

        assert cluster.launch(
            pnodes=1,
            prodCount=1,
            totalProducers=1,
            totalNodes=1+num_rodeos,
            useBiosBootFile=False,
            loadSystemContract=False,
            extraNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis",
            specificExtraNodeosArgs=specificExtraNodeosArgs)

        time.sleep(10)  # Leave rodeos nodes enough time to get fully launched

        prodNode = cluster.getNode(0)

        rodeosCluster=RodeosUtils(cluster, num_rodeos, unix_socket_option)
        rodeosCluster.start()

        Print("Testing cluster of {} rodeos nodes connecting through {}"\
            .format(num_rodeos, (lambda x: 'Unix Socket' if (x==True) else 'TCP')(unix_socket_option)))

        if enableLoadTest:
            Print("Starting load generation")
            rodeosCluster.startLoad()

        # generate blocks
        currentBlockNum=prodNode.getHeadBlockNum()
        numBlocks= currentBlockNum + 30
        assert rodeosCluster.produceBlocks(numBlocks), f"Nodeos failed to produce {numBlocks} blocks for a cluster of {num_rodeos} rodeos node"

        for i in range(num_rodeos):
            assert rodeosCluster.allBlocksReceived(numBlocks, i), f"Rodeos #{i} did not receive {numBlocks} blocks in a cluster of {num_rodeos} rodeos node"

        if enableLoadTest:
            rodeosCluster.stopLoad()

        testSuccessful=True
    finally:
        TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

# Test cases: 2,3 rodeos
numRodeos=[2, 3]
for i in [True, False]: # True means Unix-socket option, False means TCP/IP
    for j in range(len(numRodeos)):
        launch_cluster(numRodeos[j], i, enableOC)

errorCode = 0 if testSuccessful else 1
exit(errorCode)
