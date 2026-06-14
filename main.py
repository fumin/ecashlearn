import json
import logging
import os

import base58
import borsh_construct
import lmdb


def main():
    logging.basicConfig()
    lg = logging.getLogger()
    [lg.removeHandler(h) for h in lg.handlers]
    lg.addHandler(logging.StreamHandler())
    lg.setLevel(logging.INFO)
    lg.handlers[0].setFormatter(logging.Formatter("%(asctime)s.%(msecs)03d %(pathname)s:%(lineno)d %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))

    view_wallet()


class ContentValue:

    def __init__(self, value):
        self.value = value


class Output:

    def __init__(self, address, content):
        self.address = address
        self.content = content

    def __str__(self):
        jo = {"address": base58.b58encode(self.address).decode("utf-8")}
        jo["content"] = {"Value": self.content.value}
        return json.dumps(jo)


def parseOutput(bs):
    address = bs[:20]
    bs = bs[20:]

    # Rust bincode format for enums.
    contentEnum = borsh_construct.U32.parse(bs[:4])
    bs = bs[4:]

    if contentEnum == 0:
        v = borsh_construct.U32.parse(bs)
        content = ContentValue(v)
    else:
        raise Exception(f"unknown enum {contentEnum}")

    return Output(address, content)


def view_wallet():
    env_path = os.path.join(os.path.expanduser("~"), ".local/share/thunder/wallet.mdb")
    env = lmdb.open(env_path, max_dbs=1)
    utdb = env.open_db(b"utxos", create=False, dupsort=True)

    with env.begin(write=False, db=utdb) as txn:
        with txn.cursor() as cur:
            for k, v in cur.iternext():
                output = parseOutput(v)
                logging.info("output: %s", output)


def view_data():
    env_path = os.path.join(os.path.expanduser("~"), ".local/share/thunder/data.mdb")
    env = lmdb.open(env_path, max_dbs=3)
    txdb = env.open_db(b"transactions", create=False, dupsort=True)
    sudb = env.open_db(b"spent_utxos", create=False, dupsort=True)
    mvdb = env.open_db(b"mempool_version", create=False, dupsort=True)

    with env.begin(write=False, db=txdb) as txn:
        with txn.cursor() as cur:
            for k, v in cur.iternext():
                logging.info("key: %s, val: %s", k.hex(), v)


if __name__ == "__main__":
    main()
