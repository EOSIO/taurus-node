#!/usr/bin/env python3

from testUtils import Account
from testUtils import Utils
from Cluster import Cluster
from WalletMgr import WalletMgr
from Node import Node
from Node import ReturnType
from Node import BlockType
from TestHelper import TestHelper
from TestHelper import AppArgs
from testUtils import BlockLogAction
import json
import sys
import signal
import time
import subprocess
import os
import shutil

###############################################################################
# rodeos_plugin_test.py
#
# rodeos-plugin integration test
#
# This test creates a producer node (node #0), and a node (node #1) with
# rodeos-plugin enabled and with a test filter. Node #1 connects to node #0.
# This test pushes a few transactions to node #0 and queries node #1 (via the
# rodeos get_block endpoint) to see if it sees one of the block containing the
# pushed transaction. Lastly, it verifies if rodeos get_info endpoint returns a
# head_block_num.
#
###############################################################################

extraArgs=AppArgs()
extraArgs.add_bool("--eos-vm-oc-enable", "Use OC for rodeos")

# Parse command line arguments
args = TestHelper.parse_args({"-v","--clean-run","--dump-error-details","--leave-running","--keep-logs", "--signing-delay"}, extraArgs)
Utils.Debug = args.v
killAll=args.clean_run
dumpErrorDetails=args.dump_error_details
dontKill=args.leave_running
killEosInstances=not dontKill
killWallet=not dontKill
keepLogs=args.keep_logs
rodeosHTTPEndpoint = "http://127.0.0.1:8880/"
stride = 10
enableOC=args.eos_vm_oc_enable
signing_delay=args.signing_delay

walletMgr=WalletMgr(True)
cluster=Cluster(walletd=True)
cluster.setWalletMgr(walletMgr)

testSuccessful = False

def verify_nodeos_rodeos_get_block_responses(nodoes_response, rodeos_response):
    assert nodeos_response["block_num"] == rodeos_response["block_num"], "block_num do not match"
    assert nodeos_response["timestamp"] == rodeos_response["timestamp"], "timestamps do not match"
    assert nodeos_response["producer"] == response["producer"], "producer do not match"
    assert nodeos_response["producer_signature"] == response["producer_signature"], "producer_signature do not match"
    assert nodeos_response["ref_block_prefix"] == response["ref_block_prefix"], "ref_block_prefix do not match"
    assert nodeos_response["confirmed"] == response["confirmed"], "confirmed do not match"
    assert nodeos_response["id"].upper() == response["id"], "id do not match"
    assert nodeos_response["previous"].upper() == response["previous"], "previous do not match"
    assert nodeos_response["transaction_mroot"].upper() == response["transaction_mroot"], "transaction_mroot do not match"
    assert nodeos_response["action_mroot"].upper() == response["action_mroot"], "action_mroot do not match"
    assert nodeos_response["schedule_version"] == response["schedule_version"], "schedule_version do not match"

def rodeos_get_block(blockNum):
    request_body = { "block_num_or_id": blockNum }
    return Utils.runCmdArrReturnJson(['curl', '-X', 'POST', '-H', 'Content-Type: application/json', '-H', 'Accept: application/json', rodeosHTTPEndpoint + 'v1/chain/get_block', '--data', json.dumps(request_body)])

def rodeos_get_info():
    return Utils.runCmdArrReturnJson(['curl', '-X', 'POST', '-H', 'Accept: application/json', rodeosHTTPEndpoint + 'v1/chain/get_info'], trace=True)

def rodeos_get_account(account):
    request_body = {"account_name": account}
    return Utils.runCmdArrReturnJson(['curl', '-X', 'POST', '-H', 'Content-Type: application/json', '-H', 'Accept: application/json', rodeosHTTPEndpoint + 'v1/chain/get_account', '--data', json.dumps(request_body)])

try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()

    OCArg = "--eos-vm-oc-enable" if enableOC else ""
    assert cluster.launch(
        pnodes=1,
        prodCount=1,
        totalProducers=1,
        totalNodes=2,
        useBiosBootFile=False,
        loadSystemContract=False,
        extraNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis --override-chain-cpu-limits=true",
        specificExtraNodeosArgs={
            0: ("--plugin eosio::net_api_plugin --wasm-runtime eos-vm-jit --signing-delay {0}").format(signing_delay),
            1: "--disable-replay-opts --plugin b1::rodeos_plugin --rdb-options-file rocksdb_options.ini --filter-name test.filter --filter-wasm ./tests/test_filter.wasm " + OCArg
        })

    producerNodeIndex = 0
    producerNode = cluster.getNode(producerNodeIndex)

    # Create a transaction to create an account
    Utils.Print("create a new account payloadless from the producer node")
    payloadlessAcc = Account("payloadless")
    payloadlessAcc.ownerPublicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
    payloadlessAcc.activePublicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
    producerNode.createAccount(payloadlessAcc, cluster.eosioAccount)

    contractDir="unittests/test-contracts/payloadless"
    wasmFile="payloadless.wasm"
    abiFile="payloadless.abi"
    Utils.Print("Publish payloadless contract")
    trans = producerNode.publishContract(payloadlessAcc, contractDir, wasmFile, abiFile, waitForTransBlock=True)

    trx = {
        "actions": [{"account": "payloadless", "name": "doit", "authorization": [{
          "actor": "payloadless", "permission": "active"}], "data": ""}],
        "context_free_actions": [{"account": "payloadless", "name": "doit", "data": ""}],
        "context_free_data": ["a1b2c3", "1a2b3c"],
    }

    cmd = "push transaction '{}' -p payloadless".format(json.dumps(trx))
    trans = producerNode.processCleosCmd(cmd, cmd, silentErrors=False)
    assert trans, "Failed to push transaction with context free data"

    cfTrxBlockNum = int(trans["processed"]["block_num"])
    cfTrxId = trans["transaction_id"]

    # Wait until the cfd trx block is executed to become irreversible
    producerNode.waitForIrreversibleBlock(cfTrxBlockNum, timeout=30)

    Utils.Print("verify the account payloadless from producer node")
    trans = producerNode.getEosAccount("payloadless", exitOnError=False)
    assert trans["account_name"], "Failed to get the account payloadless"

    Utils.Print("verify the context free transaction from producer node, block num {}".format(cfTrxBlockNum))
    trans_from_full = producerNode.getTransaction(cfTrxId)
    assert trans_from_full, "Failed to get the transaction with context free data from the producer node"

    rodeosNodeNum = 1
    rodeosNode = cluster.getNode(rodeosNodeNum)

    rodeosNode.waitForIrreversibleBlock(cfTrxBlockNum, timeout=30)

    Utils.Print("Verify rodeos get_info endpoint works")
    head_block_num = 0
    while head_block_num < cfTrxBlockNum:
        response = rodeos_get_info()
        assert 'head_block_num' in response, "Rodeos response does not contain head_block_num, response body = {}".format(json.dumps(response))
        head_block_num = int(response['head_block_num'])
        if head_block_num < cfTrxBlockNum: time.sleep(1)

    response = rodeos_get_block(cfTrxBlockNum)
    assert response["block_num"] == cfTrxBlockNum, "Rodeos responds with wrong block"
    nodeos_response = producerNode.getBlock(cfTrxBlockNum)
    verify_nodeos_rodeos_get_block_responses(nodeos_response, response)

    if signing_delay == 0:
        Utils.Print("Verify rodeos get_account endpoint works")
        new_acct = Account("bob")
        new_acct.ownerPublicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
        new_acct.activePublicKey = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
        producerNode.createAccount(new_acct, cluster.eosioAccount)

        new_active_perms = {
            "threshold":1,
            "keys":[{"key":"EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV","weight":1}],
            "accounts":[{"permission":{"actor":new_acct.name,"permission":"active"},"weight":50}]
        }
        cmd = "set account permission " + payloadlessAcc.name + " active " + " '{}' owner".format(json.dumps(new_active_perms))
        try:
            trans = producerNode.processCleosCmd(cmd, cmd, silentErrors=True)
        except TypeError:
            # due to empty JSON response, which is expected
            pass
        time.sleep(5)

        response = rodeos_get_account(payloadlessAcc.name)
        assert response["account_name"] == payloadlessAcc.name, "Rodeos responds with wrong account name"
        assert len(response['permissions']) == 2, "Rodeos responds with wrong number of permissions"
        assert response['permissions'][0]['perm_name'] == 'active', "Rodeos responds with wrong permission name"
        assert response['permissions'][1]['perm_name'] == 'owner', "Rodeos responds with wrong permission name"
        assert response['permissions'][0]['required_auth']['threshold'] == 1, "Rodeos responds with wrong threshold"
        assert len(response['permissions'][0]['required_auth']['accounts']) == 1, "Rodeos responds with wrong number of accounts"
        assert response['permissions'][0]['required_auth']['accounts'][0]['permission']['actor'] == new_acct.name, "Rodeos responds with wrong associated key to the active permissions of " + payloadlessAcc.name
        # rodeos get_account returns public keys in PUB_K1 format
        assert response['permissions'][0]['required_auth']['keys'][0]['key'] == "PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63", "Rodeos responds with wrong public key"

    # Verify no skipped blocks
    first_block_num = 0
    for i in range(1,cfTrxBlockNum+1):
        response = rodeos_get_block(i)
        if "block_num" in response:
            if first_block_num == 0:
                first_block_num = i
            assert response["block_num"] == i, "Rodeos responds with wrong block {0}, response body = {1}".format(i, json.dumps(response))
    Utils.Print("First block in rodeos is {}".format(first_block_num))
    killTestLoopCount = 3
    for n in range(killTestLoopCount):
        # Test sigterm restart
        rodeosNode.kill(signal.SIGTERM)
        rodeosNode.relaunch(cachePopen=True)

        # verify the wasm_ql http server starting log
        Node.readlogs(rodeosNodeNum, 10,
                      "Starting wasm_ql plugin http server now after the loading of the full state", "info",
                      "Failed to read expected log: 'Starting wasm_ql plugin http server now after the loading of the full state'")

        first_block_num = rodeosNode.getHeadBlockNum()
        Utils.Print("Resetting first_block_num to {} (number of block guaranteed to be available in current database in node with rodeos-plugin)".format(first_block_num))
        head_block_num = 0
        Utils.Print("Verify rodeos get_info endpoint works after kill")
        response = rodeos_get_info()
        assert 'head_block_num' in response, "After kill, Rodeos response does not contain head_block_num, response body = {}".format(json.dumps(response))
        current_block_num = int(response['head_block_num'])
        nextBlockNum = current_block_num + int(stride/killTestLoopCount)+1 # stride+1
        while head_block_num < nextBlockNum:
            response = rodeos_get_info()
            assert 'head_block_num' in response, "After kill, Rodeos response does not contain head_block_num, response body = {}".format(json.dumps(response))
            head_block_num = int(response['head_block_num'])
            if head_block_num < nextBlockNum: time.sleep(1)
        response = rodeos_get_block(nextBlockNum)
        assert 'block_num' in response and response["block_num"] == nextBlockNum, "After kill, Rodeos responds with wrong block {0}, response body = {1}".format(nextBlockNum, json.dumps(response))
        # Verify no skipped blocks
        for i in range(first_block_num,nextBlockNum+1):
            response = rodeos_get_block(i)
            assert "block_num" in response and response["block_num"] == i, "After kill, Rodeos responds with wrong block {0}, response body = {1}".format(i, json.dumps(response))

    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
