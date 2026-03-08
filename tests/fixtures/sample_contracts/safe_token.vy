# pragma version ^0.4.0

# A well-written token contract. The detectors should report
# NO findings (or only INFO-level) on this file.

owner: public(address)
balances: public(HashMap[address, uint256])
total_supply: public(uint256)

MAX_SUPPLY: constant(uint256) = 1000000 * 10 ** 18

event Transfer:
    sender: indexed(address)
    receiver: indexed(address)
    amount: uint256

event Mint:
    receiver: indexed(address)
    amount: uint256

event OwnershipTransferred:
    old_owner: indexed(address)
    new_owner: indexed(address)

@deploy
def __init__():
    self.owner = msg.sender

@external
@nonreentrant
def transfer(to: address, amount: uint256):
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    self.balances[msg.sender] -= amount
    self.balances[to] += amount
    log Transfer(msg.sender, to, amount)

@external
@nonreentrant
def mint(to: address, amount: uint256):
    assert msg.sender == self.owner, "Not owner"
    assert self.total_supply + amount <= MAX_SUPPLY, "Exceeds max supply"
    self.total_supply += amount
    self.balances[to] += amount
    log Mint(to, amount)

@external
def transfer_ownership(new_owner: address):
    assert msg.sender == self.owner, "Not owner"
    old: address = self.owner
    self.owner = new_owner
    log OwnershipTransferred(old, new_owner)

@external
@view
def balance_of(addr: address) -> uint256:
    return self.balances[addr]
