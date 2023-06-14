#!/usr/bin/env python3
from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import signal

###############################################################
#   Producer ha test kill restart nonleader BPs
# 1: Kill one nonleader BP and cluster should continue producing block
# 2: Restart killed nonleader BP and cluster should continue producing block
# 3: Kill both non-leader BPs and cluster should stop producing blocks
# 4: Relaunch one of the killed BP and cluster should resume producing blocks.
###############################################################
def readlogs(node_num, process_time):
    return Node.readlogs(
        node_num, process_time,
        'Not producing block because producer_ha_plugin is not allowing producing.',
        'debug',
        "cluster with one BP doesn't produce block as expected"
    )

Print=Utils.Print

args = TestHelper.parse_args({"--dump-error-details","--keep-logs","-v","--kill-count","--leave-running","--clean-run"})
Utils.Debug=args.v
producers=3
totalNodes=producers+1
cluster=Cluster(walletd=True)
dumpErrorDetails=args.dump_error_details
keepLogs=args.keep_logs
dontKill=args.leave_running
killAll=args.clean_run
numBpToKill=args.kill_count
testSuccessful=False
killEosInstances=not dontKill
specificExtraNodeosArgs={}

if numBpToKill > 2:
    Utils.errorExit("Non-leader BPs to kill should be either 1 or 2")

for i in range(producers):
    Node.create_ha_config(i)
path_to_config_ha = os.getcwd()
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    extraNodeosArgs=" --resource-monitor-not-shutdown-on-threshold-exceeded"
    # sync node
    specificExtraNodeosArgs[producers] = ""
    for i in range(producers):
        specificExtraNodeosArgs[i]=" --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
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

    if numBpToKill == 1:
        # kill first nonleader BP
        if not nonLeaders[0][1].kill(signal.SIGINT):
            Utils.errorExit("Failed to shutdown node")
        if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
            Utils.errorExit("Cluster failed to produce blocks after first non-leader BP shutdown.")
        else:
            Utils.Print("Cluster in producing blocks after first non-leader BP shutdown.")

        # restart the above killed BP
        isRelaunchSuccess = nonLeaders[0][1].relaunch()
        assert isRelaunchSuccess, "Fail to relaunch BP"

        # cluster should continue production
        if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
            Utils.errorExit("Cluster failed to produce blocks after relaunching non-leader BP.")
        else:
            Utils.Print("Cluster in producing blocks after relaunching non-leader BP.")
    else:
        # kill two nonleader BP
        if not nonLeaders[0][1].kill(signal.SIGINT):
            Utils.errorExit("Failed to shutdown node")

        # Verify cluster doesn't produce blocks
        readlogs(nonLeaders[1][0], 10)
        # relaunch one nonleader BP
        isRelaunchSuccess = nonLeaders[0][1].relaunch()
        assert isRelaunchSuccess, "Fail to relaunch BP"

        #cluster resume production
        if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
            Utils.errorExit("Cluster failed to produce blocks after relaunching non-leader BP.")
        else:
            Utils.Print("Cluster in producing blocks after relaunching non-leader BP.")

    # check for hard fork 
    cluster.check_hard_fork()
    testSuccessful=True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
