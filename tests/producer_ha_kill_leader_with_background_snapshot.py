#!/usr/bin/env python3
from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import signal

###############################################################
#   Producer ha test kill restart leader BP
# 1: Kill leader BP and cluster should choose new leader and resume block production
# 2: kill one non-leader BP and cluster pauses production
# 3: Restart killed leader BP and cluster should resume producing block
###############################################################
def readlogs(node_num, process_time):
    return Node.readlogs(
        node_num, process_time,
        'No leader in the Raft group from this nodeos state at current',
        'info',
        "cluster with one BP doesn't produce block as expected"
    )
Print=Utils.Print

args = TestHelper.parse_args({"--dump-error-details","--keep-logs","-v","--leave-running","--clean-run"})
Utils.Debug=args.v
producers=3
totalNodes=producers+1
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
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    extraNodeosArgs = " --resource-monitor-not-shutdown-on-threshold-exceeded --background-snapshot-write-period-in-blocks 10"
    # sync node
    specificExtraNodeosArgs[producers] = ""
    for i in range(producers):
        specificExtraNodeosArgs[i] = " --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
        # sync node
        specificExtraNodeosArgs[producers] += " --p2p-peer-address 0.0.0.0:{}".format(9876+i)

    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False, dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True, extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up eos cluster.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    Utils.Print("Searching for leader and nonleader nodes")
    nodes = cluster.getNodes()
    Leader, nonLeaders = cluster.find_leader_and_nonleaders()

    if len(nonLeaders) != producers - 1:
        Utils.errorExit("Non-leader BPs are not alive.")

    # kill leader BP
    if not Leader[0][1].kill(signal.SIGINT):
        Utils.errorExit("Failed to shutdown node")
    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks after leader BP shutdown.")
    else:
        Utils.Print("Cluster is producing blocks after leader BP shutdown.")

    # kill non-leader BP
    if not nonLeaders[0][1].kill(signal.SIGINT):
        Utils.errorExit("Failed to shutdown node")

    # Verify cluster doesn't produce blocks
    if not readlogs(nonLeaders[1][0], 10):
        Utils.errorExit("nonleader node should not produce blocks")

    # restart the above killed BP
    isRelaunchSuccess = Leader[0][1].relaunch()
    assert isRelaunchSuccess, "Fail to relaunch BP"

    # cluster should continue production
    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks after relaunching killed leader BP.")
    else:
        Utils.Print("Cluster in producing blocks after relaunching killed leader BP.")

    # start the non leader back too
    isRelaunchSuccess = nonLeaders[0][1].relaunch()
    assert isRelaunchSuccess, "Fail to relaunch non leader BP"

    # check for hard fork
    cluster.check_hard_fork()
    testSuccessful=True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
