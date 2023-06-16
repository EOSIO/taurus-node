#!/usr/bin/env python3
from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import signal

###############################################################
#   Producer ha tests
# 1: Launch a regular cluster of nodes
# 2: Kill the cluster and relaunch it with producer_ha plugin
###############################################################

Print=Utils.Print

args = TestHelper.parse_args({"--dump-error-details","--keep-logs","-v","--leave-running","--clean-run"})
Utils.Debug=args.v
producers=3
totalNodes=producers
cluster=Cluster(walletd=True)
dumpErrorDetails=args.dump_error_details
keepLogs=args.keep_logs
dontKill=args.leave_running
killAll=args.clean_run
testSuccessful=False
killEosInstances=not dontKill
specificExtraNodeosArgs={}
ConfigDir="etc/eosio/"

def editConfigFile(nodes):
    for i in range(len(nodes)):
        filename = 'etc/eosio/node_0{}/config.ini'.format(i)
        f = open(filename, "r")
        content = f.readlines()
        with open(filename, "w") as newConfig:
            for line in content:
                if "p2p-peer-address" not in line and "producer-name" not in line:
                    newConfig.write(line)
                if "producer-name" in line:
                    newConfig.write("producer-name = eosio\n")
            newConfig.write("enable-stale-production = true")    
        
for i in range(producers):
    Node.create_ha_config(i)
path_to_config_ha = os.getcwd()
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    extraNodeosArgs=" --resource-monitor-not-shutdown-on-threshold-exceeded"
    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False, dontBootstrap=True, extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up eos cluster.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    nodes = cluster.getNodes()
    editConfigFile(nodes)
    Utils.Print("Kill all nodes")
    cluster.biosNode.kill(signal.SIGTERM)
    nodes = cluster.getNodes()
    for i in nodes:
        i.kill(signal.SIGTERM)

    for i in range(len(nodes)):
        chainArg=" --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
        isRelaunchSuccess = nodes[i].relaunch(chainArg=chainArg)
        assert isRelaunchSuccess, "Fail to relaunch BP"

    # cluster should continue production
    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks after relaunching BPs with producer_ha plugin.")
    else:
        Utils.Print("Cluster is producing blocks after relaunching BPs with producer_ha plugin.")

    # check for hard fork 
    cluster.check_hard_fork()
    testSuccessful=True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
