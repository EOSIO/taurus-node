#!/usr/bin/env python3

from testUtils import Account
from testUtils import Utils
from Cluster import Cluster
from WalletMgr import WalletMgr
from Node import Node
from Node import ReturnType
from TestHelper import TestHelper
from TestHelper import AppArgs
import json

###############################################################
# proto_abi_test
#
# Test ABI with proto3 action
# 
# This test creates a producer node add set a contract with
# protobuf action. Pushes a transaction with the protobuf action
# to the producer node and check the result.
#
###############################################################

# Parse command line arguments
args = TestHelper.parse_args({"-v","--clean-run","--dump-error-details","--leave-running","--keep-logs"})
Utils.Debug = args.v
killAll=args.clean_run
dumpErrorDetails=args.dump_error_details
dontKill=args.leave_running
killEosInstances=not dontKill
killWallet=not dontKill
keepLogs=args.keep_logs

walletMgr=WalletMgr(True)
cluster=Cluster(walletd=True)
cluster.setWalletMgr(walletMgr)

testSuccessful = False
try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    traceNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis "
    assert cluster.launch(
        pnodes=1,
        prodCount=1,
        totalProducers=1,
        totalNodes=1,
        useBiosBootFile=False,
        loadSystemContract=False,
        extraNodeosArgs=traceNodeosArgs)

    producerNode = cluster.getNode(0)

    # Create a transaction to create an account
    Utils.Print("create a new account prototest from the producer node")
    prototestAcc = Account("prototest")
    prototestAcc.ownerPublicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
    prototestAcc.activePublicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
    producerNode.createAccount(prototestAcc, cluster.eosioAccount)


    contractDir="unittests/test-contracts/proto_abi_test"
    wasmFile="proto_abi_test.wasm"
    abiFile="proto_abi_test.abi"
    Utils.Print("Publish proto_abi_test contract")
    trans = producerNode.publishContract(prototestAcc, contractDir, wasmFile, abiFile, waitForTransBlock=True)

    Utils.Print("push create action to prototest contract")
    contract="prototest"
    action="hiproto"
    data="{\"id\":1,\"type\":2,\"note\":\"abc\",\"account\":4}"
    opts="--permission prototest@active"
    trans=producerNode.pushMessage(contract, action, data, opts)
    try:
        assert(trans)
        assert(trans[0])
    except (AssertionError, KeyError) as _:
        Utils.Print("ERROR: Failed push create action to prototest contract assertion. %s" % (trans))
        raise

    # with delayed signing
    r = producerNode.pushMessage(contract, action, data, opts, dontBroadcastSkipSign=True)
    trans = r[1]
    Utils.Print("pushMessage (no broadcast) result")
    Utils.Print(trans)
    try:
        assert(r[0])
        assert(trans)
    except (AssertionError, KeyError) as _:
        Utils.Print("ERROR: Failed generate create action to prototest. %s" % (trans))
        raise

    fName = 'trx_tmp.json'
    f = open(fName, 'w')
    f.write(json.dumps(trans))
    f.close()
    Utils.Debug=True
    r = producerNode.signTransaction(fName, prototestAcc.activePublicKey)
    trans = r[1]
    Utils.Print("sign transaction result")
    Utils.Print(trans)
    fName = 'trx_tmp_signed.json'
    f = open(fName, 'w')
    f.write(json.dumps(trans))
    f.close()
    try:
        assert(r[0])
    except (AssertionError, KeyError) as _:
        Utils.Print("ERROR: Failed sign create action to prototest. %s" % (trans))
        raise
    r = producerNode.pushTransaction(fName, permissions="prototest@active")
    trans = r[1]
    try:
        assert(r[0])
    except (AssertionError, KeyError) as _:
        Utils.Print("ERROR: Failed push transaction to prototest. %s" % (trans))
        raise

    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
