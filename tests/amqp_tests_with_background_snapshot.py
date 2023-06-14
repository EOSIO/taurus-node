#!/usr/bin/env python3

from testUtils import Account
from testUtils import Utils
from testUtils import WaitSpec
from testUtils import TLSCertType
from Cluster import Cluster
from WalletMgr import WalletMgr
from Node import Node
from Node import ReturnType
from TestHelper import TestHelper
from TestHelper import AppArgs

import decimal
import re
import json
import os
import signal
from subprocess import CalledProcessError
import subprocess
import sys
import time

###############################################################
# amqp_tests
#
# tests for the amqp functionality of pause/resume of producer
#
###############################################################

AMQPS_CERTS_FILENAMES = Utils.AMQPS_CERTS_DEFAULT_FILENAMES
DEFAULT_AMQPS_ADDR = "amqps://guest:guest@127.0.0.1:5671"
Print=Utils.Print
errorExit=Utils.errorExit

cmdError=Utils.cmdError
from core_symbol import CORE_SYMBOL

appArgs = AppArgs()
appArgs.add_bool("--amqps", "Use AMQP with TLS, for nodeos (consumer) only.", action="store_true")
appArgs.add_bool("--gen-amqps-certs", "Run generate_amqps_certs.sh script prior to starting", action="store_true")
appArgs.add(flag="--amqps-address", type=str, help="Address for AMQPS for nodeos. Form amqps://<user>.<pass>@<ip>:<port>",
            default=DEFAULT_AMQPS_ADDR)
CERT_HELP = "Path for finding server and client certificates for AMQPS. There are five files expected in this directory: "
CERT_HELP += ", ".join(list(AMQPS_CERTS_FILENAMES.values()))
appArgs.add(flag="--amqps-certs-path", type=str, help=CERT_HELP,
            default="")

args = TestHelper.parse_args({"--host","--port"
                                 ,"--dump-error-details","--dont-launch","--keep-logs","-v","--leave-running","--clean-run"
                                 ,"--wallet-port","--amqp-address"}, appArgs)
server=args.host
port=args.port
debug=args.v
dumpErrorDetails=args.dump_error_details
keepLogs=args.keep_logs
dontLaunch=args.dont_launch
dontKill=args.leave_running
killAll=args.clean_run
walletPort=args.wallet_port
amqpAddr=args.amqp_address
amqps=args.amqps
amqpsAddr=args.amqps_address
if not amqps:
    amqpsAddr = None
amqpsCertsPath=args.amqps_certs_path

script_path = os.path.dirname(os.path.realpath(sys.argv[0]))
build_path = os.path.realpath(os.path.join(script_path, ".."))
if amqpsCertsPath == "":
    amqpsCertsPath = os.path.join(build_path, "amqps_certs")
genAmqpsCerts=args.gen_amqps_certs

Utils.Debug=debug
localTest=True if server == TestHelper.LOCAL_HOST else False
cluster=Cluster(host=server, port=port, walletd=True)
walletMgr=WalletMgr(True, port=walletPort)
testSuccessful=False
killEosInstances=not dontKill
killWallet=not dontKill

WalletdName=Utils.EosWalletName
ClientName="cleos"

try:
    TestHelper.printSystemInfo("BEGIN")
    cluster.setWalletMgr(walletMgr)
    Print("SERVER: %s" % (server))
    Print("PORT: %d" % (port))
    if localTest and not dontLaunch:
        cluster.killall(allInstances=killAll)
        cluster.cleanup()
        Print("Stand up cluster")

        amqProducerAccount = cluster.defProducerAccounts["eosio"]

        amqpAddrToUse = amqpAddr
        if amqps:
            amqpAddrToUse = amqpsAddr
        specificExtraNodeosArgs={ 0: " --plugin eosio::amqp_trx_plugin  --plugin eosio::amqp_trx_api_plugin --amqp-trx-startup-stopped --amqp-trx-address %s --background-snapshot-write-period-in-blocks 10" % (amqpAddrToUse),
                                  1: " --plugin eosio::amqp_trx_plugin  --plugin eosio::amqp_trx_api_plugin --amqp-trx-startup-stopped --amqp-trx-address %s --background-snapshot-write-period-in-blocks 10" % (amqpAddrToUse)}
        if amqps:
            if genAmqpsCerts:
                # should be in the same directory as this script
                cmdStr = os.path.join(script_path, "generate_amqps_certs.sh")
                Print(f"Calling '{cmdStr}'")
                try:
                    s = Utils.runCmdReturnStr(cmdStr)
                except CalledProcessError as e:
                    Print(f"'{cmdStr}' failed. output: ")
                    Print(e.output.decode("utf-8"))
                    raise e
                Print(s)
            ca_cert_path = os.path.join(amqpsCertsPath, AMQPS_CERTS_FILENAMES[TLSCertType.CA_CERT])
            cert_path = os.path.join(amqpsCertsPath, AMQPS_CERTS_FILENAMES[TLSCertType.CLIENT_CERT])
            key_path = os.path.join(amqpsCertsPath, AMQPS_CERTS_FILENAMES[TLSCertType.CLIENT_KEY])
            for k in range(2):
                flags = specificExtraNodeosArgs[k]
                flags += f" --amqps-ca-cert-perm {ca_cert_path}"
                flags += f" --amqps-cert-perm {cert_path}"
                flags += f" --amqps-key-perm {key_path}"
                specificExtraNodeosArgs[k] = flags

        Utils.startRabbitMQ(amqpAddr, amqpsAddr, amqpsCertsPath, build_path, AMQPS_CERTS_FILENAMES)
        traceNodeosArgs=" --plugin eosio::trace_api_plugin --trace-no-abis"
        if cluster.launch(totalNodes=2, totalProducers=3, pnodes=2, dontBootstrap=False, onlyBios=False, useBiosBootFile=True, specificExtraNodeosArgs=specificExtraNodeosArgs, extraNodeosArgs=traceNodeosArgs) is False:
            cmdError("launcher")
            errorExit("Failed to stand up eos cluster.")
    else:
        Print("Collecting cluster info.")
        killEosInstances=False
        Print("Stand up %s" % (WalletdName))
        walletMgr.killall(allInstances=killAll)
        walletMgr.cleanup()
        print("Stand up walletd")
        if walletMgr.launch() is False:
            cmdError("%s" % (WalletdName))
            errorExit("Failed to stand up eos walletd.")

    Print("Waiting to create queue to force consume retries")
    time.sleep(5)
    Print("Creating trx queue")
    cluster.createAMQPQueue("trx")

    Print("Validating system accounts after bootstrap")
    cluster.validateAccounts(None)

    amqProducerAccount = cluster.defProducerAccounts["eosio"]
    backup_node = cluster.getNode(1)
    backup_node.kill(signal.SIGTERM)
    backup_node.relaunch(addSwapFlags={
        "--pause-on-startup": "",
        "--producer-name": "eosio",
        "--plugin": "eosio::producer_plugin",
        "--plugin": "eosio::producer_api_plugin",
        "--signature-provider": "{}=KEY:{}".format(amqProducerAccount.ownerPublicKey, amqProducerAccount.ownerPrivateKey)
    })

    accounts=Cluster.createAccountKeys(2)
    if accounts is None:
        errorExit("FAILURE - create keys")
    testeraAccount=accounts[0]
    testeraAccount.name="testera11111"
    currencyAccount=accounts[1]
    currencyAccount.name="currency1111"

    testWalletName="test"
    Print("Creating wallet \"%s\"." % (testWalletName))
    walletAccounts=[cluster.defproduceraAccount]
    if not dontLaunch:
        walletAccounts.append(cluster.eosioAccount)
    testWallet=walletMgr.create(testWalletName, walletAccounts)

    Print("Wallet \"%s\" password=%s." % (testWalletName, testWallet.password.encode("utf-8")))

    for account in accounts:
        Print("Importing keys for account %s into wallet %s." % (account.name, testWallet.name))
        if not walletMgr.importKey(account, testWallet):
            cmdError("%s wallet import" % (ClientName))
            errorExit("Failed to import key for account %s" % (account.name))

    defproduceraWalletName="defproducera"
    Print("Creating wallet \"%s\"." % (defproduceraWalletName))
    defproduceraWallet=walletMgr.create(defproduceraWalletName)

    Print("Wallet \"%s\" password=%s." % (defproduceraWalletName, defproduceraWallet.password.encode("utf-8")))

    defproduceraAccount=cluster.defproduceraAccount

    Print("Importing keys for account %s into wallet %s." % (defproduceraAccount.name, defproduceraWallet.name))
    if not walletMgr.importKey(defproduceraAccount, defproduceraWallet):
        cmdError("%s wallet import" % (ClientName))
        errorExit("Failed to import key for account %s" % (defproduceraAccount.name))


    node=cluster.getNode(0)

    Print("Validating accounts before user accounts creation")
    cluster.validateAccounts(None)

    Print("Create new account %s via %s" % (testeraAccount.name, cluster.defproduceraAccount.name))
    node.createInitializeAccount(testeraAccount, cluster.defproduceraAccount, stakedDeposit=0, waitForTransBlock=False, exitOnError=True)

    Print("Create new account %s via %s" % (currencyAccount.name, cluster.defproduceraAccount.name))
    node.createInitializeAccount(currencyAccount, cluster.defproduceraAccount, buyRAM=200000, stakedDeposit=5000, exitOnError=True)

    Print("Validating accounts after user accounts creation")
    accounts=[testeraAccount, currencyAccount]
    cluster.validateAccounts(accounts)

    Print("**** transfer http ****")

    transferAmount="97.5321 {0}".format(CORE_SYMBOL)
    Print("Transfer funds %s from account %s to %s" % (transferAmount, defproduceraAccount.name, testeraAccount.name))
    node.transferFunds(defproduceraAccount, testeraAccount, transferAmount, "test transfer", waitForTransBlock=True)

    expectedAmount=transferAmount
    Print("Verify transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer failed")
        errorExit("Transfer verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    Print("**** Killing Main Producer Node & bios node ****")
    cluster.getNode(0).kill(signal.SIGTERM)
    cluster.discoverBiosNode().kill(signal.SIGTERM)

    Print("**** Start AMQP Testing ****")
    node = cluster.getNode(1)
    if amqpAddr:
        node.setAMQPAddress(amqpAddr)

    Print("**** Transfer with producer paused on startup, waits on timeout ****")
    transferAmount="0.0100 {0}".format(CORE_SYMBOL)
    Print("Force transfer funds %s from account %s to %s" % (
        transferAmount, defproduceraAccount.name, testeraAccount.name))
    result = node.transferFunds(defproduceraAccount, testeraAccount, transferAmount, "test transfer", expiration=3600, waitForTransBlock=False, exitOnError=False)
    transId = node.getTransId(result)
    noTrans = node.getTransaction(transId, silentErrors=True)
    if noTrans is not None:
        cmdError("FAILURE - transfer should not have been executed yet")
        errorExit("result: %s" % (noTrans))
    expectedAmount="97.5321 {0}".format(CORE_SYMBOL)
    Print("Verify no transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer executed")
        errorExit("Verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    Print("**** Resuming Producer Node ****")
    resumeResults = node.processCurlCmd(resource="producer", command="resume", payload="{}")
    Print(resumeResults)

    Print("**** Verify producing ****")
    node.waitForHeadToAdvance()

    Print("**** Verify transaction still has not executed ****")
    expectedAmount="97.5321 {0}".format(CORE_SYMBOL)
    Print("Verify no transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer executed")
        errorExit("Verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    Print("**** Start AMQP ****")
    startResults = node.processCurlCmd("amqp_trx", "start", "")
    Print(startResults)

    Print("**** Waiting for transaction ****")
    node.waitForTransInBlock(transId)

    Print("**** Verify transfer waiting in queue was processed ****")
    expectedAmount="97.5421 {0}".format(CORE_SYMBOL)
    Print("Verify transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer failed")
        errorExit("Transfer verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    Print("**** Processed Transfer ****")

    Print("**** Another transfer ****")
    transferAmount="0.0001 {0}".format(CORE_SYMBOL)
    Print("Transfer funds %s from account %s to %s" % (
        transferAmount, defproduceraAccount.name, testeraAccount.name))
    trans=node.transferFunds(defproduceraAccount, testeraAccount, transferAmount, "test transfer 2", waitForTransBlock=True)
    transId=Node.getTransId(trans)

    expectedAmount="97.5422 {0}".format(CORE_SYMBOL)
    Print("Verify transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer failed")
        errorExit("Transfer verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    Print("**** Pause producer ****")
    resumeResults = node.processCurlCmd(resource="producer", command="pause", payload="{}")
    Print(resumeResults)

    Print("**** Give time for producer to pause, pause only signals to pause on next block ****")
    time.sleep(WaitSpec.block_interval)

    Print("**** ********************************** ****")
    Print("**** Run same test with paused producer ****")

    Print("**** Transfer with producer paused, waits on timeout ****")
    transferAmount="0.0100 {0}".format(CORE_SYMBOL)
    Print("Force transfer funds %s from account %s to %s" % (
        transferAmount, defproduceraAccount.name, testeraAccount.name))
    result = node.transferFunds(defproduceraAccount, testeraAccount, transferAmount, "test transfer", expiration=3600, waitForTransBlock=False, exitOnError=False)
    transId = node.getTransId(result)
    noTrans = node.getTransaction(transId, silentErrors=True)
    if noTrans is not None:
        cmdError("FAILURE - transfer should not have been executed yet")
        errorExit("result: %s" % (noTrans))
    expectedAmount="97.5422 {0}".format(CORE_SYMBOL)
    Print("Verify no transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer executed")
        errorExit("Verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    Print("**** Resuming Backup Node ****")
    resumeResults = node.processCurlCmd(resource="producer", command="resume", payload="{}")
    Print(resumeResults)

    Print("**** Verify producing ****")
    node.waitForHeadToAdvance()

    Print("**** Waiting for transaction ****")
    node.waitForTransInBlock(transId)

    Print("**** Verify transfer waiting in queue was processed ****")
    expectedAmount="97.5522 {0}".format(CORE_SYMBOL)
    Print("Verify transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer failed")
        errorExit("Transfer verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    Print("**** Processed Transfer ****")


    Print("**** ********************************** ****")
    Print("**** Test stop/start amqp_trx_plugin ****")
    #def processCurlCmd(self, resource, command, payload, silentErrors=True, exitOnError=False, exitMsg=None, returnType=ReturnType.json):
    Print("**** Stop amqp_trx_plugin ****")
    node.processCurlCmd("amqp_trx", "stop", "")

    transferAmount="0.0100 {0}".format(CORE_SYMBOL)
    Print("Force transfer funds %s from account %s to %s" % (
        transferAmount, defproduceraAccount.name, testeraAccount.name))
    result = node.transferFunds(defproduceraAccount, testeraAccount, transferAmount, "test transfer", expiration=3600, waitForTransBlock=False, exitOnError=False)
    transId = node.getTransId(result)
    noTrans = node.getTransaction(transId, silentErrors=True)
    if noTrans is not None:
        cmdError("FAILURE - transfer should not have been executed yet")
        errorExit("result: %s" % (noTrans))
    expectedAmount="97.5522 {0}".format(CORE_SYMBOL)
    Print("Verify no transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer executed")
        errorExit("Verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    Print("**** Restart amqp_trx_plugin ****")
    node.processCurlCmd("amqp_trx", "start", "")

    Print("**** Waiting for transaction ****")
    node.waitForTransInBlock(transId)

    Print("**** Verify transfer waiting in queue was processed ****")
    expectedAmount="97.5622 {0}".format(CORE_SYMBOL)
    Print("Verify transfer, Expected: %s" % (expectedAmount))
    actualAmount=node.getAccountEosBalanceStr(testeraAccount.name)
    if expectedAmount != actualAmount:
        cmdError("FAILURE - transfer failed")
        errorExit("Transfer verification failed. Excepted %s, actual: %s" % (expectedAmount, actualAmount))

    testSuccessful=True
finally:
    TestHelper.shutdown(cluster, walletMgr, testSuccessful, killEosInstances, killWallet, keepLogs, killAll, dumpErrorDetails)

exitCode = 0 if testSuccessful else 1
exit(exitCode)