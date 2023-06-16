#!/usr/bin/env python3

from testUtils import Account
from testUtils import Utils
from testUtils import ReturnType
from Cluster import Cluster
from Node import Node
from WalletMgr import WalletMgr
from TestHelper import TestHelper
import os
import json
import time


###############################################################
# nodeos_push_event_test
#
# Loads the pushevent test contract and validates
# that nodeos pushs event to AMQP when configured to do so.
#
###############################################################

Print=Utils.Print
errorExit=Utils.errorExit

args=TestHelper.parse_args({"--dump-error-details","-v","--leave-running"
                           ,"--clean-run","--keep-logs","--amqp-address"})

pnodes=1
total_nodes = pnodes + 1
debug=args.v
dontKill=args.leave_running
dumpErrorDetails=args.dump_error_details
killAll=args.clean_run
keepLogs=args.keep_logs
amqpAddr=args.amqp_address

killWallet=not dontKill
killEosInstances=not dontKill

Utils.Debug=debug
testSuccessful=False

cluster=Cluster(walletd=True)

walletMgr=WalletMgr(True)
EOSIO_ACCT_PRIVATE_DEFAULT_KEY = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
EOSIO_ACCT_PUBLIC_DEFAULT_KEY = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
contractDir='unittests/test-contracts/pushevent'
wasmFile='pushevent.wasm'
abiFile='pushevent.abi'


def getAMQPQueueInfo(queueName):
    cmd="curl -u guest:guest -H \"content-type:application/json\" --request GET --url http://127.0.0.1:15672/api/queues/%%2F/%s " % \
        (queueName)
    return Utils.runCmdReturnStr(cmd)


try:
    assert amqpAddr, "--amqp-address option required for test"
    cluster.createAMQPQueue("events")
    time.sleep(5)
    specificExtraNodeosArgs={
        1: "--plugin eosio::event_streamer_plugin --event-tag=testit " # speculative node
    }

    os.environ["TAURUS_STREAM_RABBITS_testit"] = amqpAddr + "/events"

    # Verify events queue is empty at start
    eventQueue = getAMQPQueueInfo("events")
    Print("Queue: %s" % eventQueue)
    eventQueueJson = json.loads(eventQueue)
    Print("Msgs: %s" %  eventQueueJson["messages"])
    numMessagesInEventQueue = eventQueueJson["messages"]

    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    Print("producing nodes: %s, non-producing nodes: %d" % (pnodes, total_nodes - pnodes))

    Print("Stand up cluster")
    traceNodeosArgs = " --plugin eosio::trace_api_plugin --trace-no-abis"
    if cluster.launch(pnodes=pnodes, totalNodes=total_nodes, extraNodeosArgs=traceNodeosArgs, specificExtraNodeosArgs=specificExtraNodeosArgs) is False:
        errorExit("Failed to stand up eos cluster.")

    Print ("Wait for Cluster stabilization")
    # wait for cluster to start producing blocks
    if not cluster.waitOnClusterBlockNumSync(3):
        errorExit("Cluster never stabilized")

    Print("Creating pushevent account")
    contractaccount = Account('pushevent')
    contractaccount.ownerPublicKey = EOSIO_ACCT_PUBLIC_DEFAULT_KEY
    contractaccount.activePublicKey = EOSIO_ACCT_PUBLIC_DEFAULT_KEY
    cluster.createAccountAndVerify(contractaccount, cluster.eosioAccount, buyRAM=1000000)

    node0 = cluster.getNode(nodeId=0)
    node1 = cluster.getNode(nodeId=1)

    Print("Loading pushevent contract")
    node0.publishContract(contractaccount, contractDir, wasmFile, abiFile, waitForTransBlock=True)

    (success, trans) = node1.pushMessage("pushevent", 'push', '["testit", "route", "This is a string"]', '-p pushevent@active')

    Print("Trans: %s" % trans)
    assert success, "Should succeed"

    node1.waitForTransFinalization( Node.getTransId(trans) )

    # Verify the event is in the events queue
    eventQueue = getAMQPQueueInfo("events")
    Print("Queue: %s" % eventQueue)
    eventQueueJson = json.loads(eventQueue)
    Print("Msgs: %s" %  eventQueueJson["messages"])
    assert eventQueueJson["messages"] == numMessagesInEventQueue + 1, "event should be in the events queue"

    testSuccessful=True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)