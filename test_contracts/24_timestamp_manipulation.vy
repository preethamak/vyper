# @version ^0.3.3

owner: public(address)
unlock_time: public(uint256)

@external
def __init__():
    self.owner = msg.sender
    self.unlock_time = block.timestamp + 1

@external
def withdraw():
    assert block.timestamp >= self.unlock_time
    send(self.owner, self.balance)