#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import time


###############################################################
#   Producer ha test using snapshot to recover a node
#
# test cluster with three block producers produce blocks and
# one p2p node connecting to all producers, to
#
# 1. kill the 3rd producer node, wait for a while for the other nodes
# to generate snapshots.
# 2. start back the 3rd producer node, it should recover catch up
# through fetching snapshots from the current leader.
###############################################################


def readlogs(node_num, process_time):
    return Node.readlogs(
        node_num, process_time,
        'Not producing block because producer_ha_plugin is not allowing producing.',
        'debug',
        "cluster with one BP doesn't produce block as expected"
    )


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
# producer ids: 0...producers-1
# p2p id: producers

p2pNodeId = producers

distance = 10

for i in range(producers):
    Node.create_ha_config(i, snapshot_distance=distance)

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

    # kill standby BP
    if standbyBPId != -1:
        standbyBP.kill()

    def check_cluster(timeout=None):
        if not cluster.waitOnClusterSync(timeout=timeout, blockAdvancing=5):
            # if there is only one ha-producer, block advancing should fail
            if producers == 1 and readlogs(0, 10):
                pass
        else:
            Utils.Print("Cluster in sync")

    check_cluster()

    # check the logs to maker sure at least 2 snapshots have been created
    for cnt in range(2):
        # node 0 is running
        ha_info = nodes[0].get_producer_ha_info()
        leader_id = ha_info["leader_id"]
        found_create_snapshot = Node.readlogs(leader_id, 30,
                                             'producer_ha created snapshot:',
                                             'info',
                                             'Found created snapshot in active BP log',
                                             last_lines=0)
        assert found_create_snapshot, "Fail to found create snapshot in active BP"

    # start standby BP node
    if standbyBPId != -1:
        isRelaunchSuccess = standbyBP.relaunch()
        assert isRelaunchSuccess, "Fail to relaunch standby BP"
        # try to find apply_snapshot, check all previous logs too, 1mil should be large enough for historical logs
        found_apply_snapshot = Node.readlogs(standbyBPId, 30,
                                             'state_machine::apply_snapshot',
                                             'info',
                                             'Found state_machine::apply_snapshot in new standby BP node log',
                                             last_lines=1000000)
        assert found_apply_snapshot, "Fail to found apply_snapshot in standby BP"
        check_cluster()

    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
