rust:
    lldb: https://gist.github.com/wanyakun/314690093ea195d749fca6869ebf200e

schema:
    enforcer active_sidechain_number_to_treasury_utxo_count: int, int
    thunder wallet index_to_address: int, []byte
    thunder chain height: int, int

data stored in lmdb "~/.local/share/bip300301_enforcer/validator/signet/signet.mdb/":
    enforcer main: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/b7cc835422496a2a5d456048da28c3fb99423243/app/main.rs#L1002
    Validator new: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/7c98d4431dc4dc94c940685cb24d75e2e9454981/lib/validator/mod.rs#L423
    DBs new: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/0376bb0c2c5deed699997c09a97c8d6bd447269b/lib/validator/dbs/mod.rs#L326

withdrawal bundle id that will be acked by miner over 3 months: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/master/lib/messages.rs#L885

M5 withdrawal message: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/cc2d78a9b1489ed4c87cbe28e99b8f2d6eed1294/lib/validator/task/mod.rs#L795


1. No, NewTipReady is a sidechain internal P2P msg passed b/w thunder nodes. Enforcer provides data via foll RPC's :     
- SubscribeEvents : streams ConnectBlock DisconnectBlock events containing deposits (M5), withdrawal bundles (M6), BMM commitments (M7), and sidechain proposals
- GetTwoWayPegData
- GetChainTip

Thunder's miner (lib/miner.rs:80) calls self.cusf_mainchain.subscribe_events() to get these events, then processes deposits by calling connect_two_way_peg_data(). But the NewTipReady message that triggers L2 chain updates comes from thunder's own block production pipeline — the miner builds a block, submits a BMM request to the enforcer via CreateBmmCriticalDataTransaction, waits for the enforcer to confirm the BMM commitment appeared in a mainchain block (via the events stream), then broadcasts the new tip to peers.

2. Thunder uses LMDB (sneed crate), not flat files. The chain is stored under ~/.local/share/thunder/ (default datadir). The LMDB contains multiple DB's :
- utxos
- stxos 
- headers
- deposit_blocks
- withdrawal_bundles
- transactions 

They are all named sub-databases within the same data.mdb file. The transactions sub-database being empty is still expected if no L2-native transactions (transfers between thunder addresses, withdrawals spending deposit UTXOs) have been processed yet. Deposits from L1 create UTXO entries but don't create transaction records until those UTXOs are actually spent on the L2 chain.

You can inspect the sub-databases using mdb_stat -a thunder/ (from the lmdb-utils package) to see which databases exist and how many entries each has.

self.cusf_mainchain.subscribe_events receive:
    confirm_bmm: https://github.com/LayerTwo-Labs/thunder-rust/blob/a9d9b60b41cefc8f581b7fc1566896292ca052ec/lib/miner.rs#L69
    mine: https://github.com/LayerTwo-Labs/thunder-rust/blob/a9d9b60b41cefc8f581b7fc1566896292ca052ec/app/app.rs#L318
self.cusf_mainchain.subscribe_events preparation:
    Miner::new https://github.com/LayerTwo-Labs/thunder-rust/blob/a9d9b60b41cefc8f581b7fc1566896292ca052ec/lib/miner.rs#L29
    App::new https://github.com/LayerTwo-Labs/thunder-rust/blob/a9d9b60b41cefc8f581b7fc1566896292ca052ec/app/app.rs#L219
    miner.cusf_mainchain is of type: https://github.com/LayerTwo-Labs/thunder-rust/blob/a9d9b60b41cefc8f581b7fc1566896292ca052ec/lib/types/proto.rs#L970

self.cusf_mainchain.subscribe_events send:
    enforcer main: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/1100b6085d9ed64eeaf1b57b3c44609626bd4b23/app/main.rs#L1315
    enforcer run_connect_server starts a background server which listens on port: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/1100b6085d9ed64eeaf1b57b3c44609626bd4b23/app/main.rs#L353
    server::validator::Server is the router above, and implements subscribe_events: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/1100b6085d9ed64eeaf1b57b3c44609626bd4b23/lib/server/validator/grpc.rs#L396
    Validator does the actual work for subscribe_events, it picks up from events_rx: https://github.com/LayerTwo-Labs/bip300301_enforcer/blob/1100b6085d9ed64eeaf1b57b3c44609626bd4b23/lib/validator/mod.rs#L459
