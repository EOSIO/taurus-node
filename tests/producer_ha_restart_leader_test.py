#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import signal
import subprocess
import time
import platform

###############################################################
#   Producer ha test restart leader BP for many times
# Repeat:
# 1. Kill leader BP and cluster should choose new leader and resume block production
# 2: Restart killed leader BP and cluster should resume producing block
###############################################################


def readlogs(node_num, process_time):
    return Node.readlogs(
        node_num, process_time,
        'nodeos successfully exiting',
        'info',
        "nodeos successfully exiting as expected",
        last_lines=5
    )


Print=Utils.Print

args = TestHelper.parse_args({"--dump-error-details", "--keep-logs", "-v", "--leave-running", "--clean-run"})
Utils.Debug = True
producers = 3
totalNodes = producers + 1
cluster=Cluster(walletd=True)
dumpErrorDetails=args.dump_error_details
keepLogs=args.keep_logs
dontKill=args.leave_running
killAll=args.clean_run
testSuccessful=False
killEosInstances=not dontKill
specificExtraNodeosArgs={}

for i in range(producers):
    Node.create_ha_config(i)
path_to_config_ha = os.getcwd()
try:
    # this test requires quite some RAM to run
    mem_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
    mem_gib = mem_bytes/(1024.**3)
    if mem_gib < 16:
        Utils.Print("Machine RAM is too small. Skip this test.")
        exit(0)

    if platform.system() == 'Darwin':
        # as the macOS is being decommissioned, no musling with macOS
        Utils.Print("Skip this test for macOS")
        exit(0)

    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(kill=True, allInstances=True)
    cluster.cleanup()
    extraNodeosArgs=" --resource-monitor-not-shutdown-on-threshold-exceeded --background-snapshot-write-period-in-blocks 10"
    # sync node
    specificExtraNodeosArgs[producers] = ""
    for i in range(producers):
        specificExtraNodeosArgs[i] = " --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
        # sync node
        specificExtraNodeosArgs[producers] += " --p2p-peer-address 0.0.0.0:{}".format(9876+i)

    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False, dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True, extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up eos cluster.")

    if not cluster.waitOnClusterSync(timeout=60, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    count = 0
    max_count = 10
    while count < max_count:
        count += 1
        Utils.Print(f"Restarting tests {count}/{max_count} ...")
        Utils.Print("Searching for leader and nonleader nodes")
        nodes = cluster.getNodes()
        Leader, nonLeaders = cluster.find_leader_and_nonleaders()

        if len(nonLeaders) != producers - 1:
            Utils.errorExit("Non-leader BPs are not alive.")

        # kill non-leader
        Utils.Print(f"Killing non-leader node {nonLeaders[0][0]}")
        if not nonLeaders[0][1].kill(signal.SIGTERM):
            Utils.errorExit("Failed to shutdown node")
        if readlogs(nonLeaders[0][0], 10):
            Utils.Print("nodeos shutdown successfully")
        else:
            Utils.errorExit("nodeos did not successfully")

        Utils.Print("Sleeping for 2 seconds ...")
        time.sleep(2)

        # kill leader BP
        Utils.Print(f"Killing leader node {Leader[0][0]}")
        if not Leader[0][1].kill(signal.SIGTERM):
            Utils.errorExit("Failed to shutdown node")
        if readlogs(Leader[0][0], 10):
            Utils.Print("nodeos shutdown successfully")
        else:
            Utils.errorExit("nodeos did not successfully")

        Utils.Print("Sleeping for 2 seconds ...")
        time.sleep(2)

        # restart the above killed BPs
        isRelaunchSuccess = nonLeaders[0][1].relaunch(timeout=30, cachePopen=True)
        assert isRelaunchSuccess, "Fail to relaunch non-leader BP"

        isRelaunchSuccess = Leader[0][1].relaunch(timeout=30, cachePopen=True)
        assert isRelaunchSuccess, "Fail to relaunch leader BP"

        # cluster should continue production
        if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
            Utils.errorExit("Cluster failed to produce blocks after relaunching killed a non-leader and leader BPs.")
        else:
            Utils.Print("Cluster in producing blocks after relaunching killed a non-leader and leader BPs.")

        # check background snapshot created
        for i in range(totalNodes):
            if not Node.read_background_snapshot_logs(i, 30):
                Utils.errorExit(f"Failed to find background snapshot for node {i}")

    testSuccessful = True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
