# @version ^0.3.9
# Vulnerability: Subtraction without prior balance check
# Expected detections: unchecked_subtraction

balances: public(HashMap[address, uint256])
staked: public(HashMap[address, uint256])
rewards: public(HashMap[address, uint256])
total_supply: public(uint256)

@external
def __init__():
    self.total_supply = 1000000

@external
def withdraw_unchecked(amount: uint256):
    # VULNERABILITY: subtraction without assert balance >= amount
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)

@external
def unstake_unchecked(amount: uint256):
    # VULNERABILITY: subtraction without check
    self.staked[msg.sender] -= amount
    self.balances[msg.sender] += amount

@external
def claim_rewards():
    # VULNERABILITY: subtraction without check
    reward: uint256 = self.rewards[msg.sender]
    self.total_supply -= reward
    self.rewards[msg.sender] = 0
    self.balances[msg.sender] += reward

@external
def safe_withdraw(amount: uint256):
    # SAFE: Has balance check before subtraction
    assert self.balances[msg.sender] >= amount, "Insufficient balance"
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)
