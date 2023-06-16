#!/usr/bin/env python3
from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
from TestHelper import AppArgs
import os
import subprocess


###############################################################
#   Producer ha test
# 1: Creates two cluster of prod-ha 
# 2: verify no fork and one cluster is active and the other one receiving blocks
###############################################################
Print=Utils.Print
extraArgs=AppArgs()
extraArgs.add_bool("--net-latency", "Use relay app for net latency emulation")
args = TestHelper.parse_args({"--dump-error-details","--keep-logs","-v","--leave-running","--clean-run"}, extraArgs)
Utils.Debug=args.v
producers=6
ships=6
totalNodes=producers+ships
cluster=Cluster(walletd=True)
dumpErrorDetails=args.dump_error_details
keepLogs=args.keep_logs
dontKill=args.leave_running
killAll=args.clean_run
netLatency=args.net_latency
testSuccessful=False
killEosInstances=not dontKill
specificExtraNodeosArgs={}
NodeIds_A=[0, 1, 2]
NodeIds_B=[3, 4, 5]
shipNodeIds=[6, 7, 8, 9, 10, 11]

if netLatency:
    # --relay=listening_port:dest_ip:dest_port
    latencyConf= " --latency-in=0.001 --latency-out=0.001 --disconnect-min=3 --disconnect-max=10 --accept-rate=0.2 --drop-rate=0.9"
    relay_cmd = "bin/relay --relay=8988:127.0.0.1:18988 --relay=8989:127.0.0.1:18989 --relay=8990:127.0.0.1:18990"+latencyConf

for i in NodeIds_A:
    if netLatency:
        Node.create_ha_config(i, use_relay=True)
    else:
        Node.create_ha_config(i)
for i in NodeIds_B:
    if netLatency:
        Node.create_ha_config(i, is_active=False, use_relay=True, clstrNum=2)
    else:
        Node.create_ha_config(i, is_active=False, clstrNum=2)
path_to_config_ha = os.getcwd()
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()  

    if netLatency:
        Utils.Print("ready to start ha_relay, cmd is: " + relay_cmd)
        relay_pid = subprocess.Popen(relay_cmd.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE).pid
        Utils.Print("relay pid is " + str(relay_pid))

    extraNodeosArgs=" --resource-monitor-not-shutdown-on-threshold-exceeded"
    for i in range(producers):
        specificExtraNodeosArgs[i]=" --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
    for i in NodeIds_A:
        for j in NodeIds_B:
            specificExtraNodeosArgs[i] += " --p2p-peer-address 0.0.0.0:{}".format(9876+j)
            specificExtraNodeosArgs[j] += " --p2p-peer-address 0.0.0.0:{}".format(9876+i)
    for i, item in enumerate(shipNodeIds):
        specificExtraNodeosArgs[item] = " --p2p-peer-address 0.0.0.0:{}".format(9876+i)
    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False, dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True, extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up eos cluster.")

    if not cluster.waitOnClusterSync(timeout=120, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    nodes = cluster.getNodes()
    grpA_info = nodes[0].get_producer_ha_info()
    grpB_info = nodes[3].get_producer_ha_info()

    if not grpA_info["is_active_raft_cluster"] or grpB_info["is_active_raft_cluster"]:
        Utils.errorExit("Expected cluster A to be active and cluster B in-active")
    else:
        Utils.Print("cluster A active and cluster B in-active")

    # check for hard fork
    cluster.check_hard_fork()
    testSuccessful=True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
