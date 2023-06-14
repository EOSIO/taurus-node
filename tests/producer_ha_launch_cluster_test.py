#!/usr/bin/env python3
from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os

###############################################################
#   Producer ha test
# 1: test cluster with one block producer doesn't produce blocks
# 2: test cluster with two block producers produce blocks
# 3: test cluster with three block producers produce blocks
###############################################################

def readlogs(node_num, process_time):
    return Node.readlogs(
        node_num, process_time,
        'Not producing block because producer_ha_plugin is not allowing producing.',
        'debug',
        "cluster with one BP doesn't produce block as expected"
    )

Print=Utils.Print

args = TestHelper.parse_args({"--dump-error-details","--keep-logs","-v", "-p","--leave-running","--clean-run"})
Utils.Debug=args.v
producers=args.p
totalNodes=producers
cluster=Cluster(walletd=True)
dumpErrorDetails=args.dump_error_details
keepLogs=args.keep_logs
dontKill=args.leave_running
killAll=args.clean_run

testSuccessful=False
killEosInstances=not dontKill

specificExtraNodeosArgs={}
producerNodeId=0
for i in range(producers):
    Node.create_ha_config(i)
path_to_config_ha = os.getcwd()
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    extraNodeosArgs=" --resource-monitor-not-shutdown-on-threshold-exceeded"
    for i in range(producers):
        specificExtraNodeosArgs[i]=" --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False, dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True, extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up eos cluster.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        # if there is only one ha-producer, block advancing should fail
        if producers == 1 and readlogs(0, 10):
            testSuccessful = True
        elif producers > 1:
            Utils.errorExit("Ha cluster failed to produce block.")
    else:
        Utils.Print("Cluster in Sync")
    if producers > 1:
        cluster.check_hard_fork()
    testSuccessful=True
finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)