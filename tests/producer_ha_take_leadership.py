#!/usr/bin/env python3
from testUtils import Utils
from Cluster import Cluster
from Node import Node
from TestHelper import TestHelper
import os
import subprocess

###############################################################
#   Producer ha take leadership test
# Creates a cluster and find leader, call take_leadership api and make sure it works as expected 
###############################################################

def readlogs(node_num, process_time):
    return Node.readlogs(
        node_num, process_time,
        'Produced block',
        'info',
        "Nonleader BP successfully took leadership."
    )

def execCommand(cmd):
    Utils.Print("{}".format(cmd))
    try:
        result = Utils.runCmdReturnJson(cmd)
        Utils.Print("take_leadership result {}".format(result))
    except subprocess.CalledProcessError as ex:
        msg=ex.output.decode("utf-8")
        Utils.Print("Exception during take_leadership {}".format(msg))
        Utils.errorExit("take_leadership execution failed")

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

for i in range(producers):
    Node.create_ha_config(i, 2000, 125)
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
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    Utils.Print("Searching for leader and nonleader nodes")
    nodes = cluster.getNodes()
    Leader, nonLeaders = cluster.find_leader_and_nonleaders()

    if len(nonLeaders) != producers - 1:
        Utils.errorExit("Non-leader BPs are not alive.")
    # call leader to take leadership
    endPoint=Leader[0][1].endpointHttp
    cmd="curl -s {}/v1/producer_ha/take_leadership".format(endPoint)
    execCommand(cmd)

    if not cluster.waitOnClusterSync(timeout=30, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster is healthy producing blocks.")   

    endPoint=nonLeaders[0][1].endpointHttp
    cmd="curl -s {}/v1/producer_ha/take_leadership".format(endPoint)
    execCommand(cmd)
    if not readlogs(nonLeaders[0][1].nodeId, 20):
        Utils.errorExit("Nonleader BP didn't take leadership")

    # check for hard fork 
    cluster.check_hard_fork()
    testSuccessful=True

finally:
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
