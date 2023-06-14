## Description

The EOSIO-Taurus blockchain persists the states as snapshots to replace the shared memory file state persistent mechanism. The shared memory file solution has 2 main issues
- The shared memory file is sensitive to changes in compiler, libc, and boost versions. Changes in compiler/libc/boost will make an existing shared memory file incompatible.
- The shared memory file is not fault tolerant. If the nodeos process crashes, the shared memory file left is likely in the "Dirty DB" state which can not be used to reload the blockchain state.

It would be better to store the state in a portable format and make sure the state file creation is fault tolerant. The snapshot format is already a portable format, and EOSIO-Taurus adds mechanism to make sure crash safety.

To support persisting the blockchain state as a snapshot, the EOSIO-Taurus `chain_plugin`
- creates a snapshot during shutdown.
  - also, regularly, spawns a background process with a copy of the process state making use of the copy-on-write efficient memory cloning from `fork()`, to create a snapshot.
- loads its state from the snapshot during restarts.
- makes the OC compiler cache in-memory, and makes the fork db crash safe.

The OC compiler cache is made in-memory only so that if nodeos crashes or the nodeos binary version changes, next time when nodeos restarts it will not load the cache data it can not identify or worse it will load corrupted cached data. The side effect is that next time when nodeos restarts, the cache needs to be re-built. For long running nodes with enough available memory, this is less than an issue.

The state snapshot is guaranteed to be stable (could be old if the nodeos crashed, but guaranteed to be consistent through atomic snapshot replacement on disks using the atomic file system APIs).

## State snapshot path

Under the nodeos' data directory:

```
state/state_snapshot.bin
```

Temporary files named `.state_snapshot.bin` and `..state_snapshot.bin` may be also found there during shutdown or during background snapshot creations. They will be atomically renamed to `state_snapshot.bin` upon successful snapshot creation.

