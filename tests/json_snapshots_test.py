#!/usr/bin/env python3

from testUtils import Utils, Account
from Cluster import Cluster
from TestHelper import TestHelper
from WalletMgr import WalletMgr
from Node import Node

import signal
import json
import time
import os
import subprocess
import filecmp
import shutil

###############################################################
# json_snapshots_test
#
# Test JSON snapshot creation and restarting from JSON snapshot
#   1. Create a binary snapshot
#   2. Convert JSON snapshot from the binary snapshot
#   3. Load JSON snapshot
#   4. Create binary snapshot
#   5. Compare binary snapshots in step 1 and 5. They must be the same
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


def createJsonSnapshot(snapshotPath):
    """Create JSON format snapshot """
    cmd="programs/nodeos/nodeos --snapshot-to-json " + snapshotPath
    Utils.Print("Creating JSON snapshot: {}".format(cmd))
    proc=subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # seconds
    myTimeout = 30
    try:
        _, err = proc.communicate(timeout=myTimeout)
    except (subprocess.TimeoutExpired) as _:
        Utils.Print('ERROR: Creating JSON snapshot took longer than defined time. Hard killing nodeos instance.')
        proc.send_signal(signal.SIGKILL)
        raise RuntimeError("failed to create JSON snapshot")

    # no failure when it reaches here
    err_str = err.decode("utf-8")
    if "Completed writing snapshot:" not in err_str:
        Utils.Print("ERROR: nodeos failed during JSON snapshot creation.")
        Utils.Print("----- Begin STDERR ----")
        Utils.Print(err_str)
        Utils.Print("---- End STDERR ----")
        raise RuntimeError("failed to create JSON snapshot")


try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    traceNodeosArgs = " --plugin eosio::trace_api_plugin --trace-no-abis "
    assert cluster.launch(
        pnodes=1,
        prodCount=1,
        totalProducers=1,
        totalNodes=2,
        useBiosBootFile=False,
        loadSystemContract=False,
        extraNodeosArgs=traceNodeosArgs,
        specificExtraNodeosArgs={
            1:"--read-mode irreversible --plugin eosio::producer_api_plugin"})

    producerNodeId = 0
    irrNodeId = 1
    producerNode = cluster.getNode(producerNodeId)
    irrNode = cluster.getNode(irrNodeId)

    # Schedule a new producer to trigger new producer schedule for "global_property_object"
    newProducerAcc = Account("newprod")
    newProducerAcc.ownerPublicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
    newProducerAcc.activePublicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
    producerNode.createAccount(newProducerAcc, cluster.eosioAccount)

    setProdsStr = '{"schedule": ['
    setProdsStr += '{"producer_name":"' + newProducerAcc.name + '","block_signing_key":"' + newProducerAcc.activePublicKey + '"}'
    setProdsStr += ']}'
    cmd="push action -j eosio setprods '{}' -p eosio".format(setProdsStr)
    trans = producerNode.processCleosCmd(cmd, cmd, silentErrors=False)
    assert trans
    setProdsBlockNum = int(trans["processed"]["block_num"])

    # Wait until the block where set prods is executed become irreversible so the producer schedule
    def isSetProdsBlockNumIrr():
            return producerNode.getIrreversibleBlockNum() >= setProdsBlockNum
    Utils.waitForTruth(isSetProdsBlockNumIrr, timeout=30, sleepTime=0.1)
    # Once it is irreversible, immediately pause the producer so the promoted producer schedule is not cleared
    producerNode.processCurlCmd("producer", "pause", "")

    producerNode.kill(signal.SIGTERM)

    # Create the snapshot and rename it to avoid name conflict later on
    Utils.Print("Creating binary snapshot")
    res = irrNode.createSnapshot()
    snapshotPath = res["snapshot_name"]
    snapshotPathWithoutExt, snapshotExt = os.path.splitext(snapshotPath)
    beforeShutdownSnapshotPath = snapshotPath + "_before_shutdown" + snapshotExt
    os.rename(snapshotPath, beforeShutdownSnapshotPath)
    Utils.Print("beforeShutdownSnapshotPath: ", beforeShutdownSnapshotPath)

    # Create the JSON snapshot from the binary one
    Utils.Print("Creating JSON snapshot")
    createJsonSnapshot(beforeShutdownSnapshotPath)

    # Shut down irr node
    irrNode.kill(signal.SIGTERM)

    # Require an empty state when starting with snapshot
    shutil.rmtree(Utils.getNodeDataDir(irrNodeId, "state"), ignore_errors=True)
    shutil.rmtree(Utils.getNodeDataDir(irrNodeId, "blocks"), ignore_errors=True)

    # Load JSON snapshot
    Utils.Print("Loading JSON snapshot")
    isRelaunchSuccess = irrNode.relaunch(chainArg="--snapshot " + beforeShutdownSnapshotPath + ".json", timeout=30, cachePopen=True)
    assert isRelaunchSuccess, "Fail to relaunch"

    # Create binary snapshot
    res = irrNode.createSnapshot()

    # ensure the new snapshot is still identical
    afterShutdownSnapshotPath = res["snapshot_name"]
    assert filecmp.cmp(beforeShutdownSnapshotPath, afterShutdownSnapshotPath), "snapshot is not identical"

    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
