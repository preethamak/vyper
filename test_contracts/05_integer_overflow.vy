# @version ^0.3.3
# Vulnerability: Old Vyper version prone to integer overflow
# Expected detections: integer_overflow, compiler_version_check

MAX_SUPPLY: constant(uint256) = 1000000 * 10 ** 18

owner: public(address)
total_supply: public(uint256)
balances: public(HashMap[address, uint256])
allowances: public(HashMap[address, HashMap[address, uint256]])

@external
def __init__():
    self.owner = msg.sender
    self.total_supply = 0

@external
def mint(to: address, amount: uint256):
    assert msg.sender == self.owner, "Not owner"
    # In old Vyper, this could overflow without built-in protection
    self.total_supply += amount
    self.balances[to] += amount

@external
def transfer(to: address, amount: uint256):
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    self.balances[msg.sender] -= amount
    self.balances[to] += amount

@external
def approve(spender: address, amount: uint256):
    self.allowances[msg.sender][spender] = amount

@external
def transferFrom(sender: address, to: address, amount: uint256):
    assert self.allowances[sender][msg.sender] >= amount, "Allowance exceeded"
    assert self.balances[sender] >= amount, "Insufficient balance"
    self.allowances[sender][msg.sender] -= amount
    self.balances[sender] -= amount
    self.balances[to] += amount
