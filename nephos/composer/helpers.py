from nephos.fabric.settings import get_namespace


def get_ord_msp(opts):
    # TODO: Not highly elegant, but needed to find first MSP with peers
    msp_list = list(opts["msps"].keys())
    ord_msp = None
    for msp_name in msp_list:
        if "orderers" in opts["msps"][msp_name]:
            ord_msp = msp_name
            break
    if not ord_msp:
        raise ValueError("At least one MSP must host orderers")
    peer_namespace = get_namespace(opts, ord_msp)

    return ord_msp, peer_namespace


def get_peer_msp(opts):
    # TODO: Not highly elegant, but needed to find first MSP with peers
    msp_list = list(opts["msps"].keys())
    peer_msp = None
    for msp_name in msp_list:
        if "peers" in opts["msps"][msp_name]:
            peer_msp = msp_name
            break
    if not peer_msp:
        raise ValueError("At least one MSP must host peers")
    peer_namespace = get_namespace(opts, peer_msp)

    return peer_msp, peer_namespace
