#!/usr/bin/env python3

from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import subprocess
import signal

###############################################################################
# Producer HA Cluter Config Consistency Test - Peers Size:
# Quorum size: 4
# Peers size: 5 ===> 6
# Step 1: Start a cluster of 5 nodes, wait them to sync up
# Step 2: Stop all 5 nodes
# Step 3: Relaunch the cluster of 5 nodes, changing peers size in producer HA
#         config from 5 to 6 for each node, expecting failure
###############################################################################

args = TestHelper.parse_args({"--dump-error-details", "--keep-logs", "-v",
                              "--leave-running", "--clean-run"})
Utils.Debug = args.v
producers = 5
totalNodes = producers
quorum_size = producers // 2 + 2
peers_size = producers
cluster = Cluster(walletd=True)
dumpErrorDetails = args.dump_error_details
keepLogs = args.keep_logs
dontKill = args.leave_running
killAll = args.clean_run
testSuccessful = False
killEosInstances = not dontKill
specificExtraNodeosArgs = {}

try:
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    # Step 1: Start a cluster of 5 nodes
    stepTag = "[Step 1/3: Startup]"
    TestHelper.printSystemInfo("BEGIN")
    for i in range(producers):
        Utils.Print(f"{stepTag} Create HA config for node {i}")
        Node.create_ha_config(i, cluster_size=peers_size,
                              quorum_size=quorum_size)
    pathToConfigHa = os.getcwd()
    extraNodeosArgs = " --resource-monitor-not-shutdown-on-threshold-exceeded"
    for i in range(producers):
        extraArgs = " --plugin eosio::producer_ha_plugin "
        extraArgs += "--producer-ha-config "
        extraArgs += "{}/config_ha_{}.json".format(pathToConfigHa, i)
        specificExtraNodeosArgs[i] = extraArgs
    Utils.Print(f"{stepTag} Launch a nodeos cluster of {totalNodes} nodes")
    if cluster.launch(pnodes=producers, totalNodes=totalNodes,
                      totalProducers=producers, useBiosBootFile=False,
                      dontBootstrap=True,
                      specificExtraNodeosArgs=specificExtraNodeosArgs,
                      prod_ha=True,
                      extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit(f"{stepTag} Failed to start up cluster")
    timeout = 30
    advance = 5
    Utils.Print(f"{stepTag} Wait at most {timeout}s for cluster to sync up, "
                f"expecting {advance} advancing blocks")
    if not cluster.waitOnClusterSync(timeout=timeout, blockAdvancing=advance):
        Utils.errorExit(f"{stepTag} Cluster failed to produce blocks")
    else:
        Utils.Print(f"{stepTag} Cluster in sync")
    nodes = cluster.getNodes()
    leader, nonLeaders = cluster.find_leader_and_nonleaders()
    result = nonLeaders[0][1].get_producer_ha_info()
    leaderStr = f"{stepTag} "
    leaderStr += "v1/producer_ha/get_info API leader_id from standby BP"
    if result["leader_id"] != leader[0][0]:
        Utils.errorExit(leaderStr + " is not the leader")
    else:
        Utils.Print(leaderStr + " is the leader")

    # Step 2: Stop all 5 nodes
    stepTag = "[Step 2/3: Stop]"
    for i, node in enumerate(nodes):
        Utils.Print(f"{stepTag} Kill node {i}")
        node.kill()

    # Step 3: Relaunch all 5 nodes with a different peers size
    stepTag = "[Step 3/3: Relaunch]"
    peers_size += 1
    for i in range(producers):
        Node.create_ha_config(i, cluster_size=peers_size,
                              quorum_size=quorum_size)
    for i in range(len(nodes)):
        Utils.Print(f"{stepTag} Relaunch node {i}")
        res = nodes[i].relaunch(timeout=30, cachePopen=True)
        if res:
            Utils.errorExit(f"{stepTag} Erorr: Expected launch is failure, "
                            f"but launch is successful for node {i}")
        watch = "check failed - inconsistent peers size"
        filename = f"var/lib/node_0{i}/stderr.txt"
        last_lines = 50
        found = False
        with open(filename) as f:
            lines = f.readlines()
            for i, ln in enumerate(lines[-last_lines:]):
                if watch in ln:
                    found = True
                    for j in range(max(0, i - 10), len(lines)):
                        Utils.Print(lines[j].rstrip())
                    break
            else:
                for ln in lines[-last_lines:]:
                    Utils.Print(ln.rstrip())
        if not found:
            Utils.errorExit(f"{stepTag} Erorr: Can't find \"{watch}\" in last "
                            f"{last_lines} lines of log for node {i}")
    testSuccessful = True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False,
                        keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
