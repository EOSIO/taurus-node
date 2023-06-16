#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import signal


###############################################################
#   Producer ha test with p2p node
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
Utils.Debug = args.v
producers = args.p
totalNodes = producers
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
    extraNodeosArgs = " --resource-monitor-not-shutdown-on-threshold-exceeded"
    specificExtraNodeosArgs[p2pNodeId] = ""
    for i in range(producers):
        specificExtraNodeosArgs[i] = \
            " --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
        specificExtraNodeosArgs[p2pNodeId] += " --p2p-peer-address 0.0.0.0:{}".format(9876+i)

    if cluster.launch(pnodes=producers, totalNodes=totalNodes+1, totalProducers=producers, useBiosBootFile=False,
                      dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True,
                      extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up taurus cluster.")

    nodes = cluster.getNodes()
    standbyBPId = -1
    standbyBP = None
    if producers > 2:
        standbyBPId = 2
        standbyBP = nodes[standbyBPId]

    p2pNode = nodes[p2pNodeId]

    # stop standby BP and p2p node first
    if standbyBPId != -1:
        standbyBP.kill(signal.SIGTERM)
    p2pNode.kill(signal.SIGTERM)

    def check_cluster(timeout=None):
        if not cluster.waitOnClusterSync(timeout=timeout, blockAdvancing=5):
            # if there is only one ha-producer, block advancing should fail
            if producers == 1 and readlogs(0, 10):
                pass
        else:
            Utils.Print("Cluster in sync")

    check_cluster()

    # start p2p node
    isRelaunchSuccess = p2pNode.relaunch()
    assert isRelaunchSuccess, "Fail to relaunch p2p node"

    check_cluster()

    # start standby BP node
    if standbyBPId != -1:
        isRelaunchSuccess = standbyBP.relaunch()
        assert isRelaunchSuccess, "Fail to relaunch standby BP"
        check_cluster(timeout=60)

    if producers > 1:
        cluster.check_hard_fork()

    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
