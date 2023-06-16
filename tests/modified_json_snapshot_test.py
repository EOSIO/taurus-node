#!/usr/bin/env python3

from distutils.ccompiler import new_compiler
from subprocess import PIPE, Popen
from TestHelper import TestHelper
import subprocess
import re
import os
import shutil
import signal
import json
import argparse
import time

"""
This script automatically validates v3.0 WASMs by first modifying a v2.0 snapshot with v3.0 WASMs data (hash and associated code),
then verifying if the modified snapshot can be used to successfully run replay.

Here is an example of running the script from command line:
     ./modified_json_snapshot_test.py -n  "<dir>/build/bin/nodeos"
                                      -b  "<dir>/build/bin/eosio-blocklog"
                                      -s1 "<dir>/snapshot-01dcf0cfe4c1a6454bb85d1b128f23e366498ceea8911ce4128fc80eb38074ea.bin"
                                      -s2 "<dir>/snapshot-01e1383c8b0193c2987ebd4e12e90ba5d16e054a26c4fefb9a87a2a0ea6112aa.bin"
                                      -d  "<dir of folder `blocks`>"
                                      -w  "<dir>/path/to/contract.wasm"
                                      -a  "mycontr"
"""

arg_parser = argparse.ArgumentParser(description='Automate the test that the WASMs produced by CDT 3.0 will not break replay')
arg_parser.add_argument("-n",  "--nodeos",         help="directory of nodeos")
arg_parser.add_argument("-b",  "--eosio_blocklog", help="directory of tool eosio-blocklog")
arg_parser.add_argument("-s1", "--snapshot1",      help="a snapshot file with binary format")
arg_parser.add_argument("-s2", "--snapshot2",      help="a snapshot file with binary format")
arg_parser.add_argument("-d",  "--data_dir",       help="directory of the folder blocks that contains blocks.log and blocks.index")
arg_parser.add_argument("-w",  "--wasm",           help="the 3.0 wasm file to be tested, e.g., contract.wasm")
arg_parser.add_argument("-a",  "--account",        help="the account name to be tested, e.g, mycontr")

args = arg_parser.parse_args()
nodeos = args.nodeos
eosio_blocklog = args.eosio_blocklog
snapshot1 = args.snapshot1
snapshot2 = args.snapshot2
data_dir = args.data_dir
account_to_modify = args.account
wasm_file = args.wasm
base64_wasm_file = wasm_file + '.b64'

snapshots_bin = [snapshot1, snapshot2]
snapshots_json = []
block_numbers = []
snapshot1_block_num = 0
snapshot2_block_num = 0
modified_rows = 0
testSuccessful = False
pNodeos = None

def check_snapshot_block_num(snapshot_json_file):
    with open(snapshot_json_file, 'r+') as infile:
        for line in infile:
            if '{"block_num":' in line:
                json_object = json.loads(line)
                block_num = json_object["block_num"]
                break
    return block_num

def bin_to_json(bin_file):
    cmd = nodeos + " --snapshot-to-json " + bin_file
    try:
        print("\nConverting " + bin_file + " to JSON ...")
        pNodeos = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        outs, errs = pNodeos.communicate()
        if re.search('Completed writing snapshot', errs):
            json_file = bin_file + ".json"
            assert(os.path.exists(json_file) == True)
        else:
            print("\nFailed to convert " + bin_file + " to JSON")
            exit(1)
        pNodeos.wait()
        print("Done!")
    except subprocess.CalledProcessError as ex:
        print(ex.output)

    return json_file

def process_eosio_blocklog_cmd(cmd):
    outs = None
    errs = None
    try:
        pTrim = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        outs,errs = pTrim.communicate()
        pTrim.wait()
    except subprocess.CalledProcessError as ex:
        print(ex.output)
        exit(1)
    return outs, errs

def trim_blocklog():
    smokeTestCmd = eosio_blocklog + ' --smoke-test ' + ' --blocks-dir ' + data_dir + 'blocks'
    logSummaryCmd = eosio_blocklog + ' --summary ' + ' --blocks-dir ' + data_dir + 'blocks'
    logTrimCmd = eosio_blocklog + ' --trim-blocklog ' +  '-l ' +  str(snapshot2_block_num) + ' --blocks-dir ' + data_dir + 'blocks'
    print("\nSmoke testing of blocks.log and blocks.index in directory: " + data_dir + 'blocks' + " ...")
    process_eosio_blocklog_cmd(smokeTestCmd)
    print("Done!")
    print("\nChecking the head block number of blocks.log ...")
    outs, errs = process_eosio_blocklog_cmd(logSummaryCmd)
    summary = json.loads(errs[errs.find("{"):])
    head_block_num = summary["last_block_number"]
    print("head_block_number: " + str(head_block_num))
    assert head_block_num >= snapshot2_block_num, "the head block number of blocks.log must be great than or equal to snapshot2's block number"

    if head_block_num > snapshot2_block_num:
        print("\nTriming blocks.log as its head block number " + str(head_block_num) + " is greater than snapshot2's block number " + str(snapshot2_block_num) + " ...")
        process_eosio_blocklog_cmd(logTrimCmd)
        print("Done!")

def verify_modified_snapshot(snapshot_file):
    state_dir = data_dir + "state"
    if os.path.exists(state_dir):
        shutil.rmtree(state_dir)

    new_snapshot_bin = ""
    new_snapshot_json = ""

    print("\nReplaying from modified snapshot1 ... ")
    cmd = nodeos + " --data-dir=" + data_dir + " --chain-state-db-size-mb 15360 --contracts-console --http-validate-host=false --verbose-http-errors --plugin eosio::producer_plugin --plugin eosio::producer_api_plugin --plugin eosio::chain_api_plugin --plugin eosio::http_plugin --read-mode=irreversible --snapshot=" + snapshot_file
    try:
        pNodeos = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        while True:
            replay_output = pNodeos.stderr.readline()
            print(replay_output)
            if re.search('Finished initialization from snapshot', replay_output):
                print("Done!")
                print("\nTaking a new snapshot ...")
                time.sleep(10)
                new_snapshot = subprocess.check_output(["curl -X POST http://127.0.0.1:8888/v1/producer/create_snapshot"], shell=True, executable="/bin/bash", encoding='utf8')
                print(new_snapshot)
                assert(re.search("snapshot_name", new_snapshot))
                json_object = json.loads(new_snapshot)
                new_snapshot_bin = json_object["snapshot_name"]
                new_snapshot_json = bin_to_json(new_snapshot_bin)
                print("\nNew snapshot: " + new_snapshot_json)
                os.kill(pNodeos.pid, signal.SIGKILL)
                break
    except subprocess.CalledProcessError as ex:
        print(ex.output)
        exit(1)

    # rename `new_snapshot_bin` otherwise re-running the script would fail due to error `file already exists` caused by `create_snapshot`
    os.rename(new_snapshot_bin, new_snapshot_bin+".old")

    print("\nComparing the new snapshot with snapshot2 ...")
    diff_file = "diff.txt"
    downloaded_snapshot_json = snapshot2 + ".json"

    with open(diff_file, "w") as fp:
        try:
            cmd = "diff " + downloaded_snapshot_json + " " + new_snapshot_json
            popen=subprocess.Popen(cmd.split(), stdout=fp)
            popen.communicate()
            popen.wait()
        except subprocess.CalledProcessError as ex:
            print(f'Error: diff failed -- {ex.output}')
            exit(1)

    # find number of modified rows in the new snapshot
    found_modified_rows = 0
    with open(diff_file, "r") as fp:
        for line in fp:
            if '> ,{"name":"mycontr","recv_sequence"' in line:
                json_object = json.loads(line[3:])
                if json_object["code_hash"] == new_code_hash:
                    found_modified_rows = found_modified_rows + 1
            elif '> ,{"code_hash":' in line:
                json_object = json.loads(line[3:])
                if json_object["code_hash"] == new_code_hash and json_object["code"] == new_code:
                    found_modified_rows = found_modified_rows + 1

    assert(modified_rows == found_modified_rows)
    print("The new snapshot has the same content as snapshot2 except the changes made in snapshot1 as expected. Other transaction related difference(s) can be ignored.")
    print("See " + os.path.abspath(diff_file) + " for detail")

try:
    # convert input binary snapshots to JSON
    for snapshot in snapshots_bin:
        assert(os.path.exists(snapshot) == True)
        snapshots_json.append(bin_to_json(snapshot))

    # check the block number of each input snapshot
    for snapshot in snapshots_json:
        block_numbers.append(check_snapshot_block_num(snapshot))
    snapshot1_block_num = block_numbers[0]
    snapshot2_block_num = block_numbers[1]

    # make sure snapshot1 has smaller block number than snapshot2
    if block_numbers[0] > block_numbers[1]:
        tmp = snapshot1
        snapshot1 = snapshot2
        snapshot2 = tmp
        snapshot1_block_num = block_numbers[1]
        snapshot2_block_num = block_numbers[0]
    elif block_numbers[0] == block_numbers[1]:
        print("\n Two input snapshots must have different block numbers")
        exit(1)

    print("\nsnapshot1: " + snapshot1 + " with block number \"" + str(snapshot1_block_num) + "\"")
    print("\nsnapshot2: " + snapshot2 + " with block number \"" + str(snapshot2_block_num) + "\"")

    # trim blocks.log if its head block number is greater than snapshot2's block number
    trim_blocklog()

    # generate target contract's code
    b64Cmd = "base64 -i " + wasm_file + " -o " + base64_wasm_file
    try:
        popen = subprocess.Popen(b64Cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        popen.wait()
    except subprocess.CalledProcessError as ex:
        print(ex.output)

    # generate target contract's hash
    new_code_hash = ""
    shasumCmd = "shasum -a 256 " + wasm_file
    try:
        popen = subprocess.Popen(shasumCmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        outs,errs=popen.communicate()
        popen.wait()
        new_code_hash = outs.split()[0]
    except subprocess.CalledProcessError as ex:
        print(ex.output)

    print("\nModifying snapshot1 ...")
    old_code_hash = ""
    new_code = ""
    modify_successful = False
    try:
        with open(snapshot1 + ".json", 'r+') as infile, open(snapshot1 + ".new.json", 'w+') as outfile:
            for line in infile:
                if len(old_code_hash.strip()) and re.search(',{"code_hash":"' + old_code_hash + '"', line):
                    json_object = json.loads(line[1:]) # skip the first character comma
                    old_code = json_object["code"]
                    new_code_file = open(base64_wasm_file, 'r+')
                    new_code = new_code_file.read().strip() # remove trailing newline
                    new_code_file.close()
                    new_code_hash_line = line.replace(old_code_hash, new_code_hash)
                    new_line = new_code_hash_line.replace(old_code, new_code)
                    outfile.write(new_line)
                    modified_rows = modified_rows + 1
                    modify_successful = True
                else:
                    if re.search(',{"name":"' + account_to_modify + '","recv_sequence"', line):
                        json_object = json.loads(line[1:])
                        old_code_hash = json_object["code_hash"]
                        new_line = line.replace(old_code_hash, new_code_hash)
                        outfile.write(new_line)
                        modified_rows = modified_rows + 1
                    else:
                        outfile.write(line)
        assert(modify_successful == True)
    except subprocess.CalledProcessError as ex:
        print(ex.output)

    print("Done!")

    verify_modified_snapshot(snapshot1 + ".new.json")

    testSuccessful = True
    print('\nTEST IS SUCCESSFUL!')
finally:
    if pNodeos and pNodeos.pid:
        os.kill(pNodeos.pid, signal.SIGKILL)

exitCode = 0 if testSuccessful else 1
exit(exitCode)
