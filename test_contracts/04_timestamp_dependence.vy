# @version ^0.3.9
# Vulnerability: Timestamp dependence in access control and logic
# Expected detections: timestamp_dependence

owner: public(address)
unlock_time: public(uint256)
deadline: public(uint256)
last_action: public(uint256)
cooldown: public(uint256)

@external
def __init__():
    self.owner = msg.sender
    self.unlock_time = block.timestamp + 86400
    self.deadline = block.timestamp + 604800
    self.cooldown = 3600

@external
def withdraw_after_lock():
    # VULNERABILITY: Timestamp dependence in assert condition
    assert block.timestamp >= self.unlock_time, "Still locked"
    send(msg.sender, self.balance)

@external
def bid():
    # VULNERABILITY: Timestamp dependence in assert condition
    assert block.timestamp < self.deadline, "Auction ended"

@external
def time_gated_action():
    # VULNERABILITY: Timestamp dependence in assert condition
    assert block.timestamp - self.last_action >= self.cooldown, "Cooldown active"
    self.last_action = block.timestamp

@external
def random_selection() -> uint256:
    # VULNERABILITY: Using timestamp for pseudo-randomness
    return block.timestamp % 100
