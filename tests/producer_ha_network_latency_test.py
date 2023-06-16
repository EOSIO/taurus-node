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
from sys import stdout

###############################################################
#   Producer ha test with a mesh network:
# - test normal mesh network 
# - slowly increase network latency until nodes time out from each others
# - nodes reconnect with each others in random and may select new leader
# - blockchain eventually sync up without fork
###############################################################

def checkIfProducedBlock(node_num, process_time):
    log = "Produced block "
    log_type = "info"
    print_log = "Produced block"
    filename = 'var/lib/node_0{}/stderr.txt'.format(node_num)
    Utils.Print("checking if last 500 lines of {} contains {}".format(filename, log))
    with subprocess.Popen(['tail', '-n', '500', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as f:
        t_end = time.time() + process_time  # cluster runs for several seconds and logs are being processed
        while time.time() <= t_end:
            line = f.stdout.readline().decode("utf-8")
            if log_type in line and log in line:
                Utils.Print("{} contains line {}".format(filename, line))
                return True
        return False

Print=Utils.Print

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

relay_pid = 0
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
    stdout.flush()
    Utils.Print("checking whether there are forks...")
    cluster.check_hard_fork()
    Utils.Print("cluster has no forks, head blocks: node[0]={}, node[1]={}, node[2]={}".format(\
        nodes[0].getHeadBlockNum(),nodes[1].getHeadBlockNum(),nodes[2].getHeadBlockNum()))

    stdout.flush()
    Utils.Print("Killing relay... wait for cluster out of sync")
    os.kill(relay_pid, signal.SIGKILL)
    relay_pid = 0

    stdout.flush()
    time.sleep(5.0)
    checksum0 = nodes[0].getHeadBlockNum() * 1000000 + nodes[1].getHeadBlockNum() * 1000 + nodes[2].getHeadBlockNum()
    time.sleep(5.0)
    checksum1 = nodes[0].getHeadBlockNum() * 1000000 + nodes[1].getHeadBlockNum() * 1000 + nodes[2].getHeadBlockNum()
    if checksum0 != checksum1:
        Utils.errorExit("some of the nodes still producing, checksum0 {} != checksum1 {}, which is not expected".format(checksum0, checksum1))

    # restart relay in frequenent disconnect mode
    relay_cmd2 = relay_cmd + " --accept-rate=0.2 --latency-delta=0.03"
    Utils.Print("cluster now out of sync, checksum is {}. Restart ha_relay in latency-increasing mode, cmd is: {}".format(checksum0, relay_cmd2))
    relay_pid = subprocess.Popen(relay_cmd2.split(), stdout=subprocess.PIPE,stderr=subprocess.PIPE).pid
    Utils.Print("relay pid is " + str(relay_pid))
    stdout.flush()

    produced = [False, False, False]

    # ensure every node has a chance of producing in this latency network
    # take_leadership will be sent once there're 2 nodeos that have produced
    tries = 120
    producer_nodes_count = 0
    Utils.Print("Wait up to {} rounds or until every node has produce some blocks... ".format(tries))
    while (tries > 0 and producer_nodes_count < 3):
        Utils.Print("head blocks: node[0]={}, node[1]={}, node[2]={}, produced={}".format(\
            nodes[0].getHeadBlockNum(),nodes[1].getHeadBlockNum(),nodes[2].getHeadBlockNum(), str(produced)))
        for i in [0, 1, 2]:
            if produced[i] == False and checkIfProducedBlock(i, 1.0):
                produced[i] = True
                producer_nodes_count = producer_nodes_count + 1
                Utils.Print("node {} has produced blocks".format(i))
            elif produced[i] == False and producer_nodes_count == 2:
                cmd = "curl -s {}/v1/producer_ha/take_leadership".format(nodes[i].endpointHttp)
                nodes[i].execCommand(cmd, json=True)
        tries = tries - 1
        stdout.flush()
        time.sleep(1.0)

    Utils.Print("Killing relay, pid {}".format(relay_pid))
    os.kill(relay_pid, signal.SIGKILL)
    relay_pid = 0

    # restart relay and wait for it sync again
    Utils.Print("restart relay in normal mode, cmd is: " + relay_cmd)
    relay_pid = subprocess.Popen(relay_cmd.split()).pid
    Utils.Print("relay pid is " + str(relay_pid))
    stdout.flush()

    # wait for the cluster in sync
    if not cluster.waitOnClusterSync(timeout=120, blockAdvancing=5):
        Utils.errorExit("Cluster failed to produce blocks.")
    else:
        Utils.Print("Cluster in Sync")

    # ensure there's no fork
    Utils.Print("checking whether there are forks...")
    stdout.flush()
    cluster.check_hard_fork()
    Utils.Print("cluster has no forks, head blocks: node[0]={}, node[1]={}, node[2]={}".format(\
        nodes[0].getHeadBlockNum(),nodes[1].getHeadBlockNum(),nodes[2].getHeadBlockNum()))

    stdout.flush()
    testSuccessful = True

finally:
    if relay_pid != 0:
        Utils.Print("shutting down relay process (pid " + str(relay_pid) + ") ...")
        os.kill(relay_pid, signal.SIGKILL)
    Utils.Print("shutting down cluster ...")
    TestHelper.shutdown(cluster, None, testSuccessful, killEosInstances, False, keepLogs, killAll, dumpErrorDetails)


exitCode = 0 if testSuccessful else 1
exit(exitCode)

