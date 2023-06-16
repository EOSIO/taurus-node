#!/usr/bin/env python3

from testUtils import Account
from testUtils import Utils
from testUtils import ReturnType
from Cluster import Cluster
from WalletMgr import WalletMgr
from TestHelper import TestHelper

import random

###############################################################
# override_cpu_test
#
# Loads a longrunning test contract and validates
# that nodeos in override-chain-cpu-limits mode allows for
# an action running longer than block time.
#
###############################################################

Print=Utils.Print
errorExit=Utils.errorExit

args=TestHelper.parse_args({"--dump-error-details","-v","--leave-running"
                           ,"--clean-run","--keep-logs"})

pnodes=2
total_nodes = pnodes
debug=args.v
dontKill=args.leave_running
dumpErrorDetails=args.dump_error_details
killAll=args.clean_run
keepLogs=args.keep_logs

killWallet=not dontKill
killEosInstances=not dontKill

Utils.Debug=debug
testSuccessful=False

cluster=Cluster(walletd=True)

walletMgr=WalletMgr(True)
EOSIO_ACCT_PRIVATE_DEFAULT_KEY = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
EOSIO_ACCT_PUBLIC_DEFAULT_KEY = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
contractDir='unittests/test-contracts/longrunning'
wasmFile='longrunning.wasm'
abiFile='longrunning.abi'

try:
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    Print ("producing nodes: %s, non-producing nodes: %d" % (pnodes, total_nodes - pnodes))

    Print("Stand up cluster")
    traceNodeosArgs = " --plugin eosio::trace_api_plugin --trace-no-abis"
    specificExtraNodeosArgs={
        0:"--override-chain-cpu-limits=true"
    }
    if cluster.launch(pnodes=pnodes, totalNodes=total_nodes, extraNodeosArgs=traceNodeosArgs, specificExtraNodeosArgs=specificExtraNodeosArgs) is False:
        errorExit("Failed to stand up eos cluster.")

    Print ("Wait for Cluster stabilization")
    # wait for cluster to start producing blocks
    if not cluster.waitOnClusterBlockNumSync(3):
        errorExit("Cluster never stabilized")

    Print("Creating longrunning account")
    contractaccount = Account('longrunning')
    contractaccount.ownerPublicKey = EOSIO_ACCT_PUBLIC_DEFAULT_KEY
    contractaccount.activePublicKey = EOSIO_ACCT_PUBLIC_DEFAULT_KEY
    cluster.createAccountAndVerify(contractaccount, cluster.eosioAccount, buyRAM=70000)

    node0 = cluster.getNode(nodeId=0)
    node1 = cluster.getNode(nodeId=1)

    Print("Loading longrunning contract")
    node0.publishContract(contractaccount, contractDir, wasmFile, abiFile, waitForTransBlock=True)

    (success, trans) = node1.pushMessage("longrunning", 'run', '["This is a string to hash", 2999999]', '-p longrunning@active')

    Print ("Failure Trans: %s" % trans)
    assert not success, "Should fail because it took too long to execute"

    (success, trans) = node0.pushMessage("longrunning", 'run', '["This is a string to hash", 2999999]', '-p longrunning@active')
    Print ("Success Trans: %s" % trans)
    assert success, "Should succeed because of --override-chain-cpu-limits"

    testSuccessful=True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)