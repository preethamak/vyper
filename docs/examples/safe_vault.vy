# pragma version ^0.4.0

# ============================================================
# SAFE VAULT — All best practices applied.
# Run: vyper-guard analyze docs/examples/safe_vault.vy
# Expected score: 100/100 (A+)
# ============================================================

event Deposit:
    sender: indexed(address)
    amount: uint256

event Withdrawal:
    receiver: indexed(address)
    amount: uint256

event OwnershipTransferred:
    previous_owner: indexed(address)
    new_owner: indexed(address)

event EmergencyShutdown:
    triggered_by: indexed(address)

owner: public(address)
balances: public(HashMap[address, uint256])

@deploy
def __init__():
    self.owner = msg.sender

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value
    log Deposit(msg.sender, msg.value)

@external
@nonreentrant
def withdraw(amount: uint256):
    # Checks
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    # Effects
    self.balances[msg.sender] -= amount
    # Interactions
    send(msg.sender, amount)
    log Withdrawal(msg.sender, amount)

@external
def transfer_ownership(new_owner: address):
    assert msg.sender == self.owner, "Not owner"
    assert new_owner != empty(address), "Zero address"
    old_owner: address = self.owner
    self.owner = new_owner
    log OwnershipTransferred(old_owner, new_owner)

@external
@view
def get_balance(account: address) -> uint256:
    return self.balances[account]
