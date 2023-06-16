#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import signal
import time


###############################################################
#   Producer ha test with p2p node, expecting background snapshot created
# test cluster with three block producers produce blocks and
# one p2p node connecting to all producers
###############################################################


def readlogs(node_num, process_time):
    return Node.readlogs(
        node_num, process_time,
        'Not producing block because producer_ha_plugin is not allowing producing.',
        'debug',
        "cluster with one BP doesn't produce block as expected"
    )


Print = Utils.Print

args = TestHelper.parse_args({"--dump-error-details", "--keep-logs", "-v", "-p", "--leave-running", "--clean-run"})
Utils.Debug = True
producers = 3
totalNodes = producers + 1
cluster = Cluster(walletd=True)
dumpErrorDetails = args.dump_error_details
keepLogs = args.keep_logs
dontKill = args.leave_running
killAll = args.clean_run

testSuccessful = False
killEosInstances = not dontKill

specificExtraNodeosArgs = {}
# producer ids: 0...producers-1
# p2p id: producers
p2pNodeId = producers
for i in range(producers):
    Node.create_ha_config(i)
path_to_config_ha = os.getcwd()
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    extraNodeosArgs = " --resource-monitor-not-shutdown-on-threshold-exceeded --background-snapshot-write-period-in-blocks 10"
    specificExtraNodeosArgs[p2pNodeId] = ""
    for i in range(producers):
        specificExtraNodeosArgs[i] = \
            " --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
        specificExtraNodeosArgs[p2pNodeId] += " --p2p-peer-address 0.0.0.0:{}".format(9876+i)

    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False,
                      dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True,
                      extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up taurus cluster.")

    if not cluster.waitOnClusterSync(timeout=60, blockAdvancing=12):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    Utils.Print(f"Checking background snapshot: round 1 ...")

    for i in range(producers+1):
        if not Node.read_background_snapshot_logs(i, 30):
            Utils.errorExit(f"Failed to find background snapshot for node {i}")

    nodes = cluster.getNodes()

    # kill them with kill, first one gets kill -9
    first = True
    for node in nodes:
        if first:
            node.kill(signal.SIGKILL)
            first = False
        else:
            node.kill(signal.SIGTERM)

    Utils.Print("Killed all nodes")

    # relaunch the cluster
    for node in nodes:
        isRelaunchSuccess = node.relaunch()
        assert isRelaunchSuccess, "Fail to relaunch node"

    if not cluster.waitOnClusterSync(timeout=60, blockAdvancing=12):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    Utils.Print(f"Checking background snapshot: round 2 ...")

    for i in range(producers+1):
        if not Node.read_background_snapshot_logs(i, 30):
            Utils.errorExit(f"Failed to find background snapshot for node {i}")

    Utils.Print(f"Checking background snapshot: round 3 ...")
    Utils.Print("Sleep 6 seconds ...")
    time.sleep(6)

    for i in range(producers+1):
        if not Node.read_background_snapshot_logs(i, 30):
            Utils.errorExit(f"Failed to find background snapshot for node {i}")

    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
