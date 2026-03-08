# @version ^0.2.16
# Vulnerability: Extremely old compiler version with known bugs
# Expected detections: compiler_version_check, integer_overflow

# This version is very old and has known security issues:
# - No built-in overflow protection
# - Known compiler bugs

owner: public(address)
balance: public(uint256)

@external
def __init__():
    self.owner = msg.sender
    self.balance = 0

@external
@payable
def deposit():
    self.balance += msg.value

@external
def withdraw(amount: uint256):
    assert msg.sender == self.owner
    assert self.balance >= amount
    self.balance -= amount
    send(msg.sender, amount)
