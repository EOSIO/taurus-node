#!/usr/bin/env python3

from testUtils import Account
from testUtils import Utils
from Cluster import Cluster
from WalletMgr import WalletMgr
from Node import Node
from Node import ReturnType
from TestHelper import TestHelper
from TestHelper import AppArgs
import json
import subprocess
import signal
import shutil


###############################################################
# persist_data_false_test
#
# Test a sync node which starts with a snapshot and --persist-data=false
# 
# This test creates a producer node and a syn node.
# Then, it create a snapshot from the producer and use the created snapshot to start the sync node
# with --persis_data=false option
#
###############################################################

# Parse command line arguments
args = TestHelper.parse_args({"-v","--clean-run","--dump-error-details","--leave-running","--keep-logs"})
Utils.Debug = args.v
killAll=args.clean_run
dumpErrorDetails=args.dump_error_details
dontKill=args.leave_running
killEosInstances=not dontKill
killWallet=not dontKill
keepLogs=args.keep_logs

walletMgr=WalletMgr(True)
cluster=Cluster(walletd=True)
cluster.setWalletMgr(walletMgr)

testSuccessful = False
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    traceNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis "
    assert cluster.launch(
        pnodes=1,
        prodCount=1,
        totalProducers=1,
        totalNodes=2,
        useBiosBootFile=False,
        loadSystemContract=False,
        extraNodeosArgs=traceNodeosArgs)

    producerNode = cluster.getNode(0)
    syncNode = cluster.getNode(1)
    syncNode.kill(signal.SIGTERM)

    # Wait until the block 10
    def isBlock10Irr():
        return producerNode.getIrreversibleBlockNum() >= 10
    Utils.waitForTruth(isBlock10Irr, timeout=30, sleepTime=0.1)
    
    # create a new snapshot from producer node
    Utils.Print("Creating binary snapshot")
    res = producerNode.createSnapshot()
    snapshot = res["snapshot_name"]

    # start the sync node with the snapshot
    syncNodeDataDir = Utils.getNodeDataDir(syncNode.nodeId)
    # Require an empty state when starting with snapshot
    shutil.rmtree(Utils.getNodeDataDir(syncNode.nodeId, "state"), ignore_errors=True)
    shutil.rmtree(Utils.getNodeDataDir(syncNode.nodeId, "blocks"), ignore_errors=True)
    
    syncNode.cmd = syncNode.cmd + f" --persist-data=false --snapshot={snapshot}"
    syncNode.relaunch()
    syncNode.waitForHeadToAdvance(timeout=30)

    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
