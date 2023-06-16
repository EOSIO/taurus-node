#!/usr/bin/env python3
from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import signal
import subprocess
import time

###############################################################
#   Producer ha test disconnect/reconnect all BPs 
# 1: diconnect all BPs and verify none of the BPs producing blocks
# 2: reconnect BPs and verify cluster is stable.
###############################################################
def readlogs(node_num, process_time):
    return Node.readlogs(
        node_num, process_time,
        'No leader in the Raft group from this nodeos state at current',
        'info',
        "Disconnected cluster of BPs not producing blocks as expected."
    )
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

# --relay=listening_port:dest_ip:dest_port
relay_cmd = "bin/relay --relay=8988:127.0.0.1:18988 --relay=8989:127.0.0.1:18989 --relay=8990:127.0.0.1:18990"

for i in range(producers):
    Node.create_ha_config(i, use_relay=True)
path_to_config_ha = os.getcwd()
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    Utils.Print("ready to start ha_relay, cmd is: " + relay_cmd)
    relay_pid = subprocess.Popen(relay_cmd.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE).pid
    Utils.Print("relay pid is " + str(relay_pid))

    extraNodeosArgs=" --resource-monitor-not-shutdown-on-threshold-exceeded"
    for i in range(producers):
        specificExtraNodeosArgs[i]=" --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False, dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True, extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up eos cluster.")

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    nodes = cluster.getNodes()

    if not cluster.waitOnClusterSync(timeout=40, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks after leader BP shutdown.")
    else:
        Utils.Print("Cluster is producing blocks after leader BP shutdown.")

    # kill relay to disconnect all BPs
    Utils.Print("Killing relay... wait for cluster out of sync")
    os.kill(relay_pid, signal.SIGKILL)
    relay_pid = 0

    time.sleep(5.0)
    if cluster.waitOnClusterSync(timeout=50, blockAdvancing=5):
        Utils.errorExit("cluster still in sync without relay, which is not expected. (something wrong with the config settings?)")
        
    # Verify cluster doesn't produce blocks
    for i in range(len(nodes)):
        if not readlogs(i, 10):
            Utils.errorExit("disconnected nodes are producing blocks")

    # restart relay 
    Utils.Print("restart start ha_relay, cmd is: " + relay_cmd)
    relay_pid = subprocess.Popen(relay_cmd.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE).pid
    Utils.Print("relay pid is " + str(relay_pid))

    # cluster should continue production
    if not cluster.waitOnClusterSync(timeout=60, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks after relaunching killed leader BP.")
    else:
        Utils.Print("Cluster in producing blocks after relaunching killed leader BP.")

    # ensure there's no fork
    Utils.Print("checking whether there are forks...")
    cluster.check_hard_fork()
    Utils.Print("cluster has no forks, head blocks: node[0]={}, node[1]={}, node[2]={}".format(\
        nodes[0].getHeadBlockNum(),nodes[1].getHeadBlockNum(),nodes[2].getHeadBlockNum()))
    testSuccessful=True

finally:
    if relay_pid != 0:
        Utils.Print("shutting down relay process (pid " + str(relay_pid) + ") ...")
        os.kill(relay_pid, signal.SIGKILL)
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
