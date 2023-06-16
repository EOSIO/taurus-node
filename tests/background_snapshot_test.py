#!/usr/bin/env python3

import json
import os
import platform
import re
import shutil
import sys
import time
import traceback

from datetime import datetime
from testUtils import Utils
from testUtils import Account
from testUtils import ReturnType
from TestHelper import TestHelper
from TestHelper import AppArgs
from Node import Node

from WalletMgr import WalletMgr

class CleosException(Exception):
    pass

class BackgroundSnapshotTest:
    def __init__(self, args):
        self.args = args
        self.node_id = 0
        self.keosd = WalletMgr(True, TestHelper.DEFAULT_PORT, TestHelper.LOCAL_HOST,
                      TestHelper.DEFAULT_WALLET_PORT, TestHelper.LOCAL_HOST)
        self.nodeos = Node(TestHelper.LOCAL_HOST, TestHelper.DEFAULT_PORT, self.node_id, walletMgr=self.keosd)
        self.data_dir = Utils.getNodeDataDir(self.node_id)
        self.config_dir = Utils.getNodeConfigDir(self.node_id)
        self.http_server_address = "%s:%s" % (TestHelper.LOCAL_HOST, TestHelper.DEFAULT_PORT)
        self.sleep_s = 10

    def safeRemovePath(self, pth, msg):
        try:
            if Utils.Debug:
                Utils.Print("%s: removing '%s'" % (msg, pth))
            shutil.rmtree(pth)
        except Exception as e:
            Utils.Print(e)
            Utils.Print("%s: error attempting to remove %s" % (msg, pth))

    # make a fresh data dir
    def createDataDirs(self):
        self.safeRemovePath(self.data_dir, "createDataDirs")
        if Utils.Debug:
            Utils.Print("Creating '%s'" % (self.data_dir))
        os.makedirs(self.data_dir)
        os.makedirs(os.path.join(self.data_dir, "state"))

    # kill nodeos and keosd and clean up dir
    def cleanEnv(self):
        self.keosd.killall(True)
        WalletMgr.cleanup()
        Node.killAllNodeos()
        # self.nodeos.kill()
        if not self.args.keep_logs:
            self.safeRemovePath(self.data_dir, "cleanEnv")
        time.sleep(self.sleep_s)

    # start keosd, nodeos
    def startEnv(self, isFirstRun=True, snapshotFile=None):
        if isFirstRun:
            self.createDataDirs()
        else:
            # remove nodeos state dirs
            self.safeRemovePath(os.path.join(self.data_dir, 'blocks'), 'startEnv')
            #self.safeRemovePath(os.path.join(self.data_dir, 'state'), 'startEnv')
        self.keosd.launch()
        nodeos_plugins = ("--plugin %s --plugin %s --plugin %s"
        " --plugin %s --plugin %s") % ("eosio::chain_plugin",
            "eosio::chain_api_plugin",
            "eosio::producer_plugin",
            "eosio::producer_api_plugin",
            "eosio::http_plugin")

        nodeos_flags = (" --data-dir=%s"
                        " --config-dir=%s"
                        " --http-server-address %s") % (self.data_dir,
                         self.config_dir,
                         self.http_server_address)
        nodeos_flags += " --p2p-max-nodes-per-host 3 --chain-state-db-size-mb 16384"
        nodeos_flags += " --access-control-allow-origin='*' --http-validate-host=false"
        nodeos_flags += " --wasm-runtime eos-vm-jit --disable-subjective-billing 1"
        nodeos_flags += " --cpu-effort-percent 100  --signature-cpu-billable-pct 0"
        nodeos_flags += " --last-block-cpu-effort-percent 100 --last-block-time-offset-us 0"
        nodeos_flags += " --max-transaction-time 475 --p2p-accept-transactions true"
        nodeos_flags += " --http-max-response-time-ms 475 --max-body-size 4194304"
        nodeos_flags += " --abi-serializer-max-time-ms 1000000000"
        nodeos_flags += " --background-snapshot-write-period-in-blocks 10"
        if snapshotFile is not None:
            nodeos_flags += " --snapshot %s" % (snapshotFile)
        else:
            nodeos_flags += " --genesis-json ./tests/load_generator_genesis.json"
        if(platform.system() == "Linux"):
            nodeos_flags += " --eos-vm-oc-enable --eos-vm-oc-compile-threads 4"
        start_nodeos_cmd = ("%s -e -p eosio %s %s ") % (Utils.EosServerPath,
                             nodeos_plugins, nodeos_flags)
        self.nodeos.launchCmd(start_nodeos_cmd, self.node_id)

        time.sleep(self.sleep_s)

    def run(self):
        testSuccessful = False
        try:
            self.startEnv()
            time.sleep(self.sleep_s)

            # make sure the background snapshot is created
            Utils.Print("Waiting for Block 10")
            self.nodeos.waitForBlock(10)
            state_snapshot = os.path.join(self.data_dir, "state", "state_snapshot.bin")
            snapshotCreated = False
            nAttempts = 5
            Utils.Print("Waiting for snapshot to be created")
            while not snapshotCreated and nAttempts > 0:
                snapshotCreated = os.path.exists(state_snapshot)
                time.sleep(0.5)
                nAttempts -= 1
            if not snapshotCreated:
                Utils.errorExit("Nodeos failed to create state_snapshot.bin")
            else:
                Utils.Print("Nodeos created state_snapshot.bin")

            # save a copy of the background snapshot created
            state_snapshot = os.path.join(self.data_dir, "state", "state_snapshot.bin")
            copydst = "./state_snapshot.bin"
            shutil.copyfile(state_snapshot, copydst)

            # `kill -9`'ed the nodeos here
            Utils.Print("kill -9 nodeos, then start it back with the in place state_snapshot.bin")
            Node.killAllNodeos()
            time.sleep(self.sleep_s)
            self.startEnv(isFirstRun=False)
            Utils.Print("Waiting for Block 55 - by then the background snapshot creation has run for 10 times")
            self.nodeos.waitForBlock(55)

            # `kill -9`'ed the nodeos again
            Utils.Print("kill -9 nodeos, then start it back with a state_snapshot.bin copied out")
            Node.killAllNodeos()
            # start back nodeos with the save background snapshot created
            os.remove(os.path.join(self.data_dir, "state", "shared_memory.bin"))
            time.sleep(self.sleep_s)
            self.startEnv(isFirstRun=False, snapshotFile=copydst)
            Utils.Print("Waiting for block 55 - by then the background snapshot creation has run for 10 times")
            self.nodeos.waitForBlock(55)

            Utils.Print("Tests completed")
            testSuccessful = True
        except Exception as e:
            if not self.args.leave_running:
                self.cleanEnv()
            raise e
        if not self.args.leave_running:
            self.cleanEnv()


if __name__ == "__main__":
    Print = Utils.Print
    errorExit = Utils.errorExit
    cmdError = Utils.cmdError

    appArgs = AppArgs()
    appArgs.add_bool("--debug", "Print debugging output", action="store_true")
    appArgs.add(flag="--snapshot-path", type=str, help="Full path to snapshot",
                default="./tests/bootstrap_snapshot.bin")

    args = TestHelper.parse_args({"--keep-logs", "--leave-running"}, appArgs)
    Utils.Debug = args.debug
    args.trace = args.debug

    script_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    build_path = os.path.realpath(os.path.join(script_path, ".."))

    bgSnapshotTest = BackgroundSnapshotTest(args)
    bgSnapshotTest.run()
