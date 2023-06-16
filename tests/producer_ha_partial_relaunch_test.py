#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import subprocess
import signal

###############################################################################
# Producer HA Partial Relaunch Test:
# Take turns to restart two of all three nodes and check that they are in sync.
# Step 1 : Start a cluster of 3 nodes: node #0, node #1, node #2
# Step 2 : Stop all 3 nodes
# Step 3a: Relaunch - node #1 and node #2, leaving node #0 unstarted
# Step 3b: Check    - node #1 and node #2 are in sync
# Step 3c: Stop     - node #1 and node #2
# Step 4a: Relaunch - node #0 and node #2, leaving node #1 unstarted
# Step 4b: Check    - node #0 and node #2 are in sync
# Step 4c: Stop     - node #0 and node #2
# Step 5a: Relaunch - node #0 and node #1, leaving node #2 unstarted
# Step 5b: Check    - node #0 and node #1 are in sync
# Step 5c: Stop     - node #0 and node #1
###############################################################################

args = TestHelper.parse_args({"--dump-error-details", "--keep-logs", "-v",
                              "--leave-running", "--clean-run"})
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
    pathToConfigHa = os.getcwd()
    extraNodeosArgs = " --resource-monitor-not-shutdown-on-threshold-exceeded"
    for i in range(producers):
        extraArgs = " --plugin eosio::producer_ha_plugin "
        extraArgs += "--producer-ha-config "
        extraArgs += "{}/config_ha_{}.json".format(pathToConfigHa, i)
        specificExtraNodeosArgs[i] = extraArgs

    # Step 1: Start a cluster of 3 nodes
    Utils.Print("--- Start Up a Cluster of {} Nodes ---".format(totalNodes))
    if cluster.launch(pnodes=producers, totalNodes=totalNodes,
                      totalProducers=producers, useBiosBootFile=False,
                      dontBootstrap=True,
                      specificExtraNodeosArgs=specificExtraNodeosArgs,
                      prod_ha=True,
                      extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("[Startup] Failed to start up cluster")
    timeout = 30
    advance = 5
    Utils.Print("[Startup] Wait at most {}s for cluster to sync up, "
                "expecting {} advancing blocks".format(timeout, advance))
    if not cluster.waitOnClusterSync(timeout=timeout, blockAdvancing=advance):
        Utils.errorExit("[Startup] Cluster failed to produce blocks")
    else:
        Utils.Print("[Startup] Cluster in sync")
    nodes = cluster.getNodes()
    leader, nonLeaders = cluster.find_leader_and_nonleaders()
    result = nonLeaders[0][1].get_producer_ha_info()
    leaderStr = "[Startup] "
    leaderStr += "v1/producer_ha/get_info API leader_id from standby BP"
    if result["leader_id"] != leader[0][0]:
        Utils.errorExit(leaderStr + " is not the leader")
    else:
        Utils.Print(leaderStr + " is the leader")

    # Step 2: Stop all 3 nodes
    Utils.Print("--- Stop All {} Nodes ---".format(totalNodes))
    for i, node in enumerate(nodes):
        Utils.Print("[Stop] Kill node {}".format(i))
        node.kill()

    # Step 3-5: Take turns to relaunch, check, and stop 2 of all 3 nodes
    for x in range(len(nodes)):
        roundStr = "Round {} of {}".format(x + 1, totalNodes)
        Utils.Print("--- {} ---".format(roundStr))
        runningNodesId = []
        for i in range(len(nodes)):
            if i == x:
                Utils.Print("[{}] Leave node {} unstarted".format(roundStr, i))
            else:
                Utils.Print("[{}] Relaunching node {}".format(roundStr, i))
                res = nodes[i].relaunch(cachePopen=True)
                if not res:
                    Utils.errorExit(
                        "[{}] Failed to relaunch node {}".format(roundStr, i))
                runningNodesId.append(i)
        timeout = 60
        advance = 10
        Utils.Print("[{}] Wait at most {}s for cluster to sync up, "
                    "expecting {} advancing blocks".format(
                        roundStr, timeout, advance))
        if not cluster.waitOnClusterSync(timeout=timeout,
                                         blockAdvancing=advance):
            Utils.errorExit(
                "[{}] Cluster failed to produce block".format(roundStr))
        else:
            Utils.Print("[{}] Cluster is producing again".format(roundStr))
        for i in runningNodesId:
            Utils.Print("[{}] Kill node {}".format(roundStr, i))
            nodes[i].kill()
    testSuccessful = True

finally:
    # might try to kill processes even when they are gone, ok but not elegant
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False,
                        keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
