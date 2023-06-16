#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import signal


###############################################################
#   Producer ha paused API
# Creates a cluster and find leader, call APIs and verify results
# - v1/producer/paused
# - v1/producer_ha/get_info
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

for i in range(producers):
    Node.create_ha_config(i)
path_to_config_ha = os.getcwd()
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
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

    if len(nonLeaders) != producers - 1:
        Utils.errorExit("Non-leader BPs are not alive.")

    # call leader APIs
    # paused
    result = Leader[0][1].get_paused()
    if result != "false":
        Utils.errorExit("v1/producer/paused API result is not 'false' for leader BP")
    else:
        Utils.Print("v1/producer/paused API result is 'false' for leader BP")

    # get_info
    result = Leader[0][1].get_producer_ha_info()
    if result["leader_id"] != Leader[0][0]:
        Utils.errorExit("v1/producer_ha/get_info API leader_id from leader is not the leader")
    else:
        Utils.Print("v1/producer_ha/get_info API leader_id from leader is the leader")
    leader_ha_info = result

    # call follower APIs

    # paused
    result = nonLeaders[0][1].get_paused()
    if result != "true":
        Utils.errorExit("v1/producer/paused API result is not 'true' for the standby BP")
    else:
        Utils.Print("v1/producer/paused API result is 'true' for the standby BP")

    # get_info
    result = nonLeaders[0][1].get_producer_ha_info()
    if result["leader_id"] != Leader[0][0]:
        Utils.errorExit("v1/producer_ha/get_info API leader_id from standby BP is not the leader")
    else:
        Utils.Print("v1/producer_ha/get_info API leader_id from standby BP is the leader")

    standby_ha_info = result

    # fields should all exists
    for k in ["is_active_raft_cluster", "quorum_size", "last_committed_block_num", "leader_id", "peers"]:
        if k not in leader_ha_info:
            Utils.errorExit("{} field missing from producer_ha/get_info response".format(k))
    for p in leader_ha_info["peers"]:
        for k in ["id", "address", "listening_port"]:
            if k not in p:
                Utils.errorExit("{} field missing from producer_ha/get_info peer response {}".format(k, p))

    Utils.Print("All fields expected exist in producer_ha/get_info response")

    # fields should be the same, except the last_commit_block_num which may be different
    leader_ha_info.pop("last_committed_block_num", None)
    standby_ha_info.pop("last_committed_block_num", None)
    if leader_ha_info != standby_ha_info:
        Utils.errorExit("v1/producer_ha/get_info returned by leader and standby BP are not the same.")

    # kill 2 followers
    for p in nonLeaders:
        p[1].kill(signal.SIGTERM)

    # waiting for 10 seconds
    if cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster still produced blocks after all standby BPs are stopped.")
    else:
        Utils.Print("Cluster production stopped as expected after stopping all standby BPs.")

    # get_info from previous leader
    result = Leader[0][1].get_producer_ha_info()
    if result["leader_id"] != -1:
        Utils.errorExit("v1/producer_ha/get_info API leader_id is not -1 when there is no leader")
    else:
        Utils.Print("v1/producer_ha/get_info API leader_id is -1 when there is no leader")

    testSuccessful = True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
