#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import subprocess
import signal


###############################################################
#   Producer ha paused API
# Creates a cluster with
# - is_active_raft_cluster = True or False
# and switch it to simulate region switch
###############################################################


Print = Utils.Print
args = TestHelper.parse_args({"--dump-error-details", "--keep-logs", "-v", "--leave-running", "--clean-run"})
Utils.Debug = args.v
producers = 3
totalNodes = producers
cluster = Cluster(walletd=True)
dumpErrorDetails = args.dump_error_details
keepLogs = args.keep_logs
dontKill = args.leave_running
killAll = args.clean_run
testSuccessful = False
killEosInstances = not dontKill
specificExtraNodeosArgs = {}

try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    for i in range(producers):
        Node.create_ha_config(i)
    path_to_config_ha = os.getcwd()
    extraNodeosArgs = " --resource-monitor-not-shutdown-on-threshold-exceeded"
    for i in range(producers):
        specificExtraNodeosArgs[i] = \
            " --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(
                path_to_config_ha, i)
    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False,
                      dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True,
                      extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up eos cluster.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    nodes = cluster.getNodes()
    Leader, nonLeaders = cluster.find_leader_and_nonleaders()

    # get_info
    result = nonLeaders[0][1].get_producer_ha_info()
    if result["leader_id"] != Leader[0][0]:
        Utils.errorExit("v1/producer_ha/get_info API leader_id from standby BP is not the leader")
    else:
        Utils.Print("v1/producer_ha/get_info API leader_id from standby BP is the leader")

    # now turn the Raft cluster to standby mode
    for node in nodes:
        node.kill()

    for i in range(producers):
        Node.create_ha_config(i, None, None, is_active=False)

    for node in nodes:
        res = node.relaunch(cachePopen=True)
        if not res:
            Utils.errorExit("Relaunching node failed")
    cluster.setNodes(nodes)

    # wait for 10 blocks in case the producer_ha still have some blocks to apply to the producer_plugin
    if cluster.waitOnClusterSync(timeout=45, blockAdvancing=10):
        Utils.errorExit("Cluster still produce blocks.")
    else:
        Utils.Print("Cluster not producing")

    result = nodes[0].get_producer_ha_info()
    if result["leader_id"] == -1:
        Utils.errorExit("v1/producer_ha/get_info API leader_id is -1. Not expected")
    else:
        Utils.Print("v1/producer_ha/get_info API leader_id is not -1. Expected.")

    if result["is_active_raft_cluster"]:
        Utils.errorExit("v1/producer_ha/get_info API is_active_raft_cluster is True. Not expected")
    else:
        Utils.Print("v1/producer_ha/get_info API is_active_raft_cluster is False. Expected")

    # now turn the Raft cluster back to active mode
    for node in nodes:
        node.kill()

    for i in range(producers):
        Node.create_ha_config(i, None, None, is_active=True)

    for node in nodes:
        res = node.relaunch(cachePopen=True)
        if not res:
            Utils.errorExit("Relaunching node failed")
    cluster.setNodes(nodes)

    if not cluster.waitOnClusterSync(timeout=60, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster is producing again")

    Leader, nonLeaders = cluster.find_leader_and_nonleaders()

    # get_info
    result = nonLeaders[0][1].get_producer_ha_info()
    if result["leader_id"] != Leader[0][0]:
        Utils.errorExit("v1/producer_ha/get_info API leader_id from standby BP is not the leader")
    else:
        Utils.Print("v1/producer_ha/get_info API leader_id from standby BP is the leader")

    testSuccessful = True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
