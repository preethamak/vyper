# @version ^0.4.0
# Fully secure contract — should have ZERO findings
# Expected: Score 100/100, Grade A+

event Deposit:
    sender: indexed(address)
    amount: uint256

event Withdrawal:
    receiver: indexed(address)
    amount: uint256

event OwnershipTransferred:
    previous: indexed(address)
    new_owner: indexed(address)

owner: public(address)
balances: public(HashMap[address, uint256])
total_deposits: public(uint256)

@deploy
def __init__():
    self.owner = msg.sender
    self.total_deposits = 0

@external
@payable
@nonreentrant
def deposit():
    self.balances[msg.sender] += msg.value
    self.total_deposits += msg.value
    log Deposit(msg.sender, msg.value)

@external
@nonreentrant
def withdraw(amount: uint256):
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    self.balances[msg.sender] -= amount
    self.total_deposits -= amount
    send(msg.sender, amount)
    log Withdrawal(msg.sender, amount)

@external
def transfer_ownership(new_owner: address):
    assert msg.sender == self.owner, "Not owner"
    old: address = self.owner
    self.owner = new_owner
    log OwnershipTransferred(old, new_owner)

@view
@external
def get_balance(account: address) -> uint256:
    return self.balances[account]
