# pragma version ^0.4.0

# ============================================================
# SIMPLE TOKEN — A few medium-severity issues.
# Run: vyper-guard analyze docs/examples/token.vy
# ============================================================

event Transfer:
    sender: indexed(address)
    receiver: indexed(address)
    amount: uint256

event Approval:
    owner: indexed(address)
    spender: indexed(address)
    amount: uint256

name: public(String[32])
symbol: public(String[8])
decimals: public(uint8)
total_supply: public(uint256)
balances: public(HashMap[address, uint256])
allowances: public(HashMap[address, HashMap[address, uint256]])
owner: public(address)

@deploy
def __init__(_name: String[32], _symbol: String[8], _supply: uint256):
    self.name = _name
    self.symbol = _symbol
    self.decimals = 18
    self.total_supply = _supply
    self.balances[msg.sender] = _supply
    self.owner = msg.sender

@external
def transfer(to: address, amount: uint256) -> bool:
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    self.balances[msg.sender] -= amount
    self.balances[to] += amount
    log Transfer(msg.sender, to, amount)
    return True

@external
def approve(spender: address, amount: uint256) -> bool:
    self.allowances[msg.sender][spender] = amount
    log Approval(msg.sender, spender, amount)
    return True

@external
def transfer_from(sender: address, to: address, amount: uint256) -> bool:
    assert self.allowances[sender][msg.sender] >= amount, "Not approved"
    assert self.balances[sender] >= amount, "Insufficient balance"
    self.allowances[sender][msg.sender] -= amount
    self.balances[sender] -= amount
    self.balances[to] += amount
    log Transfer(sender, to, amount)
    return True

# ISSUE: Missing event emission when minting (MEDIUM)
# ISSUE: Unprotected state change if no owner check detected (HIGH)
@external
def mint(to: address, amount: uint256):
    assert msg.sender == self.owner, "Not owner"
    self.total_supply += amount
    self.balances[to] += amount

@external
@view
def balance_of(account: address) -> uint256:
    return self.balances[account]
