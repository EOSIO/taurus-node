#!/usr/bin/env python3
import json
import time
import sys
import os

from testUtils import Utils
from Cluster import Cluster
from TestHelper import TestHelper
from Node import Node
from WalletMgr import WalletMgr
from core_symbol import CORE_SYMBOL

# trace_plugin_test
#
# test starts cluster with 1 node, executes transaction and checks if trace API returns block with this transaction
#
###############################################################

Print=Utils.Print
errorExit=Utils.errorExit
cmdError=Utils.cmdError

def get_block(params: str, node: Node) -> json:
    base_cmd_str = ("curl -s http://%s:%s/v1/") % (TestHelper.LOCAL_HOST, node.port)
    cmd_str = base_cmd_str + "trace_api/get_block  -X POST -d " + ("'{\"block_num\":%s}'") % params
    return Utils.runCmdReturnJson(cmd_str)

try:
    args = TestHelper.parse_args({"--host","--port","--wallet-port","--dump-error-details","--keep-logs","-v","--leave-running","--clean-run", "--signing-delay"})
    server=args.host
    port=args.port
    Utils.Debug = args.v
    dontKill=args.leave_running
    killAll=args.clean_run
    signing_delay=args.signing_delay
    dumpErrorDetails=args.dump_error_details
    walletPort=args.wallet_port
    keepLogs=args.keep_logs

    cluster=Cluster(walletd=True, defproduceraPrvtKey=None, )
    walletMgr=WalletMgr(True, port=walletPort)
    accounts = []
    cluster.setWalletMgr(walletMgr)

    sleep_s = 2
    testSuccessful=False
    killEosInstances=not dontKill
    killWallet=not dontKill
    TestHelper.printSystemInfo("BEGIN")
    cluster.setWalletMgr(walletMgr)
    Print("SERVER: %s" % (server))
    Print("PORT: %d" % (port))

    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    walletMgr.cleanup()
    Print("Stand up cluster")

    account_names = ["alice", "bob", "charlie"]
    abs_path = os.path.abspath(os.getcwd() + '/../unittests/contracts/eosio.token/eosio.token.abi')
    traceNodeosArgs = " --plugin eosio::trace_api_plugin --trace-rpc-abi eosio.token={} --signing-delay {}".format(abs_path, signing_delay)
    cluster.launch(totalNodes=1, extraNodeosArgs=traceNodeosArgs)
    walletMgr.launch()
    testWalletName="testwallet"
    testWallet=walletMgr.create(testWalletName, [cluster.eosioAccount, cluster.defproduceraAccount])
    cluster.validateAccounts(None)
    accounts=Cluster.createAccountKeys(len(account_names))
    node = cluster.getNode(0)
    for idx in range(len(account_names)):
        accounts[idx].name =  account_names[idx]
        walletMgr.importKey(accounts[idx], testWallet)
    for account in accounts:
        Utils.Print("Creating initialized account for {}".format(account))
        node.createInitializeAccount(account, cluster.eosioAccount, buyRAM=1000000, stakedDeposit=5000000, waitForTransBlock=True, exitOnError=True)
    time.sleep(sleep_s)
    Utils.Print("Testing environment started.")

    node = cluster.getNode(0)
    for account in accounts:
        assert(node.verifyAccount(account) is not None)

    expectedAmount = Node.currencyIntToStr(5000000, CORE_SYMBOL)
    account_balances = []
    for account in accounts:
        amount = node.getAccountEosBalanceStr(account.name)
        assert(amount == expectedAmount)
        account_balances.append(amount)

    xferAmount = Node.currencyIntToStr(123456, CORE_SYMBOL)
    trans = node.transferFunds(accounts[0], accounts[1], xferAmount, "test transfer a->b")
    transId = Node.getTransId(trans)
    blockNum = Node.getTransBlockNum(trans)

    assert(node.getAccountEosBalanceStr(accounts[0].name) == Utils.deduceAmount(expectedAmount, xferAmount))
    assert(node.getAccountEosBalanceStr(accounts[1].name) == Utils.addAmount(expectedAmount, xferAmount))
    time.sleep(sleep_s)

    # verify trans via node api before calling trace_api RPC
    blockFromNode = node.getBlock(blockNum)
    assert("transactions" in blockFromNode)
    isTrxInBlockFromNode = False
    for trx in blockFromNode["transactions"]:
        assert("trx" in trx)
        assert("id" in trx["trx"])
        if (trx["trx"]["id"] == transId) :
            isTrxInBlockFromNode = True
            break
    assert(isTrxInBlockFromNode)

    # verify trans via trace_api by calling get_block RPC
    blockFromTraceApi = get_block(blockNum, node)
    assert("transactions" in blockFromTraceApi)
    isTrxInBlockFromTraceApi = False
    for trx in blockFromTraceApi["transactions"]:
        assert("id" in trx)
        if (trx["id"] == transId) :
            isTrxInBlockFromTraceApi = True
            Utils.Print("Found transaction {} in block {}".format(transId, blockNum))
            break
    assert(isTrxInBlockFromTraceApi)

    testSuccessful=True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)