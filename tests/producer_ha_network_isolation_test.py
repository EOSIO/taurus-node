#!/usr/bin/env python3
from testUtils import Utils
from Cluster import Cluster
from TestHelper import TestHelper
from Node import Node
import json
import os
import subprocess
import time
import re
import signal

###############################################################
#   Producer ha test with isolated network, it will test:
# - normal producer ha in a 3-node connected network
# - disconnection of the all network sessions
# - network isolation in such a way that the original BP lost connection with the rest of 2 BP nodes
# - the rest 2 BPs connect each other back and elect the new leader (which is different from the original BP)
# - the origin BP connect back and sync up without any fork
###############################################################

def checkIfProducedBlock(node_num, process_time):
    return Node.readlogs(node_num, process_time, 'Produced block', 'info', 'Produced block')

args = TestHelper.parse_args({"--dump-error-details","--keep-logs","-v", "--leave-running","--clean-run"})
Utils.Debug=args.v
producers=3 # args.p
totalNodes=producers
cluster=Cluster(walletd=True)
dumpErrorDetails=args.dump_error_details
keepLogs=args.keep_logs
dontKill=args.leave_running
killAll=args.clean_run

# --relay=listening_port:dest_ip:dest_port
relay_cmd = "bin/relay --relay=8988:127.0.0.1:18988 --relay=8989:127.0.0.1:18989 --relay=8990:127.0.0.1:18990"

testSuccessful=False
killEosInstances=not dontKill

specificExtraNodeosArgs={}
producerNodeId=0
for i in range(producers):
    Node.create_ha_config(i, use_relay=True)
path_to_config_ha = os.getcwd()
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    Utils.Print("ready to start ha_relay, cmd is: " + relay_cmd)
    relay_pid = subprocess.Popen(relay_cmd.split()).pid
    Utils.Print("relay pid is " + str(relay_pid))

    extraNodeosArgs=" --resource-monitor-not-shutdown-on-threshold-exceeded"
    for i in range(producers):
        specificExtraNodeosArgs[i]=" --plugin eosio::producer_ha_plugin --producer-ha-config {}/config_ha_{}.json".format(path_to_config_ha, i)
    if cluster.launch(pnodes=producers, totalNodes=totalNodes, totalProducers=producers, useBiosBootFile=False, dontBootstrap=True, specificExtraNodeosArgs=specificExtraNodeosArgs, prod_ha=True, extraNodeosArgs=extraNodeosArgs) is False:
        Utils.errorExit("Failed to stand up eos cluster.")

    # wait for relay until cluster is in-sync
    nodes=cluster.getNodes()
    tries = 10
    while tries > 0:
        if cluster.waitOnClusterSync(blockAdvancing=5):
            Utils.Print("Cluster is currently in Sync, connected with relay, head block of node[0] is {}".format(nodes[0].getHeadBlockNum()))
            break
        else:
            Utils.Print("Cluster not in sync, waiting ...")
            time.sleep(5)
            tries = tries - 1

    if tries == 0:
        Utils.errorExit("Cluster not in sync, but expected in sync")

    # ensure it is no forks
    Utils.Print("checking whether there are forks...")
    cluster.check_hard_fork()
    Utils.Print("cluster has no forks, head blocks: node[0]={}, node[1]={}, node[2]={}".format(\
        nodes[0].getHeadBlockNum(),nodes[1].getHeadBlockNum(),nodes[2].getHeadBlockNum()))

    # found out which node is the active producer 
    leaders, nonleaders = cluster.find_leader_and_nonleaders()
    if len(leaders) == 0:
        Utils.errorExit("No leader!!!")

    producing_node_id = leaders[0][0]

    Utils.Print("Leader is {}. Killing relay... wait for cluster out of sync".format(producing_node_id))
    os.kill(relay_pid, signal.SIGKILL)
    relay_pid = 0

    # wait until out of sync
    time.sleep(5.0)
    if cluster.waitOnClusterSync(blockAdvancing=5):
        Utils.errorExit("cluster still in sync without relay, which is not expected. (something wrong with the config settings?)")

    head_block_num = nodes[producing_node_id].getHeadBlockNum()

    # shutdown the active producer
    Utils.Print("killing the active BP node {} at head_block_num {}".format(producing_node_id, head_block_num))
    nodes[producing_node_id].kill()

    # restart relay
    Utils.Print("cluster now out of sync. ready to start ha_relay again, cmd is: " + relay_cmd)
    relay_pid = subprocess.Popen(relay_cmd.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE).pid
    Utils.Print("relay pid is " + str(relay_pid))

    # ensure every node has a chance of producing in this frequency disconnect network
    tries = 60
    Utils.Print("Wait up to {} rounds or until some node has produce some blocks... ".format(tries))
    rest_produced = False
    while rest_produced == False and tries > 0:
        for i in [0, 1, 2]:
            if producing_node_id == i:
                continue 
            new_head = nodes[i].getHeadBlockNum()
            if new_head > head_block_num + 1 and checkIfProducedBlock(i, 0.1):
                Utils.Print("node {} has produced blocks after shutting down the original BP node {} (at block {}), its current head is {}".format(i, producing_node_id, head_block_num, new_head))
                rest_produced = True
                break
        tries = tries - 1
        time.sleep(1.0)

    # make sure the rest of the cluster is producing
    if rest_produced == False:
        Utils.errorExit("cluster not producing after shutting down the original BP node {} at head_block_num {}".format(producing_node_id, head_block_num))

    # relaunch the original active producer
    Utils.Print("relauch the original BP node {}".format(producing_node_id))
    nodes[producing_node_id].relaunch()

    # wait for the cluster in sync
    tries = 20
    while tries > 0:
        if cluster.waitOnClusterSync(blockAdvancing=5):
            Utils.Print("Cluster is currently in Sync, head block of node[0] is {}".format(nodes[0].getHeadBlockNum()))
            break
        else:
            Utils.Print("Cluster not in sync, waiting ...")
            time.sleep(5)
            tries = tries - 1

    if tries == 0:
        Utils.errorExit("Cluster not in sync, but expected in sync")

    # ensure there's no fork
    Utils.Print("checking whether there are forks...")
    cluster.check_hard_fork()
    Utils.Print("cluster has no forks, head blocks: node[0]={}, node[1]={}, node[2]={}".format(\
        nodes[0].getHeadBlockNum(),nodes[1].getHeadBlockNum(),nodes[2].getHeadBlockNum()))

    testSuccessful = True

finally:
    if relay_pid != 0:
        Utils.Print("shutting down relay process (pid " + str(relay_pid) + ") ...")
        os.kill(relay_pid, signal.SIGKILL)
    Utils.Print("shutting down cluster ...")
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)


exitCode = 0 if testSuccessful else 1
exit(exitCode)

