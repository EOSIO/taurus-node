#!/usr/bin/env python3

from Cluster import Cluster
from Node import Node
from TestHelper import AppArgs
from TestHelper import TestHelper
from testUtils import Account
from testUtils import Utils
from WalletMgr import WalletMgr

import json
import subprocess

###############################################################################
# rodeos_plugin_verify_sig_test.py
#
# rodeos-plugin verify RSA signatures test
#
# This test creates a producer node (node #0), and a node (node #1) with
# rodeos-plugin enabled. The test pushes a transaction to node #0, to a
# contract that verifies RSA signatures. Only if the signature is verified
# can the transaction be processed. Then from the rodeos-plugin-enabled node #1
# we verify the blocks are exactly the same between the 2 nodes.
#
###############################################################################

PUBLIC_KEY = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"

# Parse command line arguments
extraArgs = AppArgs()
args = TestHelper.parse_args({"-v", "--clean-run", "--dump-error-details",
                              "--leave-running", "--keep-logs"}, extraArgs)
Utils.Debug = args.v
killAll = args.clean_run
dumpErrorDetails = args.dump_error_details
dontKill = args.leave_running
killEosInstances = not dontKill
killWallet = not dontKill
keepLogs = args.keep_logs
rodeosHTTPEndpoint = "http://127.0.0.1:8880/"

walletMgr = WalletMgr(True)
cluster = Cluster(walletd=True)
cluster.setWalletMgr(walletMgr)


def rodeos_get_info():
    return Utils.runCmdArrReturnJson(
                    ["curl", "-X", "POST",
                     "-H", "Accept: application/json",
                     rodeosHTTPEndpoint + "v1/chain/get_info"], trace=True)


def rodeos_get_block(block_num):
    request_body = {"block_num_or_id": block_num}
    return Utils.runCmdArrReturnJson(
                    ["curl", "-X", "POST",
                     "-H", "Content-Type: application/json",
                     "-H", "Accept: application/json",
                     rodeosHTTPEndpoint + "v1/chain/get_block",
                     "--data", json.dumps(request_body)])


def verify_nodeos_rodeos_get_block_responses(nodeos_resp, rodeos_resp):
    assert nodeos_resp["block_num"] == rodeos_resp["block_num"], \
           "block_num do not match"
    assert nodeos_resp["timestamp"] == rodeos_resp["timestamp"], \
           "timestamps do not match"
    assert nodeos_resp["producer"] == rodeos_resp["producer"], \
           "producer do not match"
    assert (nodeos_resp["producer_signature"] ==
            rodeos_resp["producer_signature"]), \
           "producer_signature do not match"
    assert (nodeos_resp["ref_block_prefix"] ==
            rodeos_resp["ref_block_prefix"]), \
           "ref_block_prefix do not match"
    assert nodeos_resp["confirmed"] == rodeos_resp["confirmed"], \
           "confirmed do not match"
    assert nodeos_resp["id"].upper() == rodeos_resp["id"], \
           "id do not match"
    assert nodeos_resp["previous"].upper() == rodeos_resp["previous"], \
           "previous do not match"
    assert (nodeos_resp["transaction_mroot"].upper() ==
            rodeos_resp["transaction_mroot"]), \
           "transaction_mroot do not match"
    assert (nodeos_resp["action_mroot"].upper() ==
            rodeos_resp["action_mroot"]), \
           "action_mroot do not match"
    assert (nodeos_resp["schedule_version"] ==
            rodeos_resp["schedule_version"]), \
           "schedule_version do not match"


testSuccessful = False

try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.killall(allInstances=killAll)
    cluster.cleanup()
    assert cluster.launch(
        pnodes=1,
        prodCount=1,
        totalProducers=1,
        totalNodes=2,
        useBiosBootFile=False,
        loadSystemContract=False,
        extraNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis",
        specificExtraNodeosArgs={0: ("--plugin b1::rodeos_plugin " +
                                     "--rdb-options-file " +
                                     "rocksdb_options.ini")})

    producerNodeIndex = 0
    producerNode = cluster.getNode(producerNodeIndex)

    # Push transaction
    Utils.Print("create a new account alice from the producer node")
    aliceAcc = Account("alice")
    aliceAcc.ownerPublicKey = PUBLIC_KEY
    aliceAcc.activePublicKey = PUBLIC_KEY
    producerNode.createAccount(aliceAcc, cluster.eosioAccount)

    contractDir = "unittests/test-contracts/verify_rsa"
    wasmFile = "verify_rsa.wasm"
    abiFile = "verify_rsa.abi"
    Utils.Print("Publish verify_rsa contract")
    trans = producerNode.publishContract(aliceAcc, contractDir, wasmFile,
                                         abiFile, waitForTransBlock=True)
    trx = {
        "actions": [{
            "account": "alice",
            "name": "verrsasig",
            "authorization": [{
                "actor": "alice",
                "permission": "active"}],
            "data": {
                "message": "message to sign",
                "signature": "476455bfe93c2fdc226b3c0f325feb9fbf22234e92e417aa22ed1b24ee0b127ba2cab513bb4089488fb70199a53a736f0baf3db3d4bb630b6574f685259125dc18777a9e8f66a853ea69edf04965a80aa35b2bbf4b46f50fd744b676864a5933e53c9b2cc7d8dcc7edebba58d762652350d8a3ca64265319135cb92621731824452dfc839d4412874f1ada5ff41b2bbbb2d10d878125bbf9632787d2c0ec4c3912eb07187a103623298b2233a07b051e0e34151b7e1ed6095bfe3d4994284013bd6998d7a84ca6725497dce9bb7c3fe6e2481b5b050ad0a5d91622945cf62a9f22524dc32bb2cdf9a1cb0b77be0a1dd3bc58d29899bfa5a2688f6353d75e4c16",
                "exponent": "10001",
                "modulus": "e06bccbf7d2cbe0d5420d62e8448a8b4165eb2b6431e64e5bbdf84580f3c4dfb49da522a6f66897a5a8b8c6c8bb448cb7b51a08e5f70c199a4e13e567b4966369a503226418c10838c109c3b37cca70157dbbcad7682bdf348b625f88492260780d3bc2efa94f2d3018a74df68ccfa6edcd01531b7a546af170f74116dabb1ab4951798e389c37ae12c5b4845e9e2a287ff4d23fa785c137a8bb3af6b147c260aabc0d1c92a3e429cdaf7b3d1903df53569e0eb284e530fd23eef57cd07c8468362bd63c41b8abdad3645dab9e74bc49d8fc040bb16f2afb167bb6e9a95454e124f8c3fc3c46420862c5f42f0c82f08a04b3309312a23161740ef6d38b3eead5"
            }
        }]
    }
    cmd = "push transaction '{}' -p alice".format(json.dumps(trx))
    trans = producerNode.processCleosCmd(cmd, cmd, silentErrors=False)
    Utils.Print("trans={}".format(trans))
    assert trans, "Failed to push transaction"

    # Verification
    block_num = int(trans["processed"]["block_num"])
    trx_id = trans["transaction_id"]

    producerNode.waitForIrreversibleBlock(block_num, timeout=30)

    Utils.Print("Verify account alice from producer node")
    trans = producerNode.getEosAccount("alice", exitOnError=False)
    assert trans["account_name"], "Failed to get the account alice"

    Utils.Print("Verify the transaction from producer node, " +
                "block num {}".format(block_num))
    trans_from_full = producerNode.getTransaction(trx_id)
    assert trans_from_full, \
           "Failed to get the transaction with data from the producer node"
    rodeosNode = cluster.getNode(1)
    rodeosNode.waitForIrreversibleBlock(block_num, timeout=30)
    Utils.Print("Verify get info with rodeos plugin")
    head_block_num = 0
    while head_block_num < block_num:
        response = rodeos_get_info()
        assert "head_block_num" in response, \
               ("Rodeos response does not contain head_block_num, " +
                "response body = {}".format(json.dumps(response)))
        head_block_num = int(response["head_block_num"])
        if head_block_num < block_num:
            time.sleep(1)
    response = rodeos_get_block(block_num)
    assert response["block_num"] == block_num, \
           "Rodeos responds with wrong block"
    nodeos_response = producerNode.getBlock(block_num)
    Utils.Print("Verify get block with rodeos plugin")
    verify_nodeos_rodeos_get_block_responses(nodeos_response, response)
    Utils.Print("Push transaction directly to rodeos-plugin-enabled node")
    del trx["actions"][0]["authorization"]
    cmd = ("./programs/cleos/cleos --url {} ".format(rodeosHTTPEndpoint) +
           "push transaction '{}' ".format(json.dumps(trx)) +
           "--use-old-send-rpc --return-failure-trace 0 --skip-sign " +
           "--permission alice")
    output = subprocess.check_output(cmd, shell=True)
    output_dict = json.loads(output)
    assert "processed" in output_dict, \
           "\"processed\" not found, transaction might not be successful"
    Utils.Print("output_dict[\"processed\"]={}".format(
                output_dict["processed"]))
    testSuccessful = True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances,
                        killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
