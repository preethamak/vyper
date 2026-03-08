# @version ^0.2.8

balances: public(HashMap[address, uint256])

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value

@external
def withdraw(amount: uint256):
    # no balance check
    self.balances[msg.sender] -= amount
    send(msg.sender, amount)