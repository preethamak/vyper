# @version ^0.3.9
# Vulnerability: Sending ETH inside loops (DoS vector)
# Expected detections: send_in_loop

struct Recipient:
    addr: address
    share: uint256

owner: public(address)
recipients: public(DynArray[address, 100])
shares: public(HashMap[address, uint256])

@external
def __init__():
    self.owner = msg.sender

@external
def add_recipient(addr: address, share: uint256):
    assert msg.sender == self.owner, "Not owner"
    self.recipients.append(addr)
    self.shares[addr] = share

@external
@payable
def distribute_profits():
    # VULNERABILITY: send in loop — if one recipient reverts, all fail
    total: uint256 = msg.value
    for recipient: address in self.recipients:
        share: uint256 = self.shares[recipient]
        send(recipient, total * share / 10000)

@external
@payable
def distribute_with_raw_call():
    # VULNERABILITY: raw_call in loop
    total: uint256 = msg.value
    for recipient: address in self.recipients:
        share: uint256 = self.shares[recipient]
        raw_call(recipient, b"", value=total * share / 10000)

@external
@payable
def batch_payout(addrs: DynArray[address, 50], amounts: DynArray[uint256, 50]):
    # VULNERABILITY: send in loop with external input
    for i: uint256 in range(50):
        if i >= len(addrs):
            break
        send(addrs[i], amounts[i])
