# @version ^0.3.9
# Vulnerability: State changes without event emissions
# Expected detections: missing_event_emission

owner: public(address)
admin: public(address)
fee_rate: public(uint256)
paused: public(bool)
whitelist: public(HashMap[address, bool])

event OwnershipTransferred:
    previous_owner: indexed(address)
    new_owner: indexed(address)

@external
def __init__():
    self.owner = msg.sender
    self.admin = msg.sender
    self.fee_rate = 100
    self.paused = False

@external
def set_owner(new_owner: address):
    # VULNERABILITY: State change without event emission
    assert msg.sender == self.owner, "Not owner"
    self.owner = new_owner

@external
def set_admin(new_admin: address):
    # VULNERABILITY: State change without event emission
    assert msg.sender == self.owner, "Not owner"
    self.admin = new_admin

@external
def set_fee_rate(new_rate: uint256):
    # VULNERABILITY: State change without event emission
    assert msg.sender == self.owner, "Not owner"
    assert new_rate <= 10000, "Rate too high"
    self.fee_rate = new_rate

@external
def toggle_pause():
    # VULNERABILITY: State change without event emission
    assert msg.sender == self.admin, "Not admin"
    self.paused = not self.paused

@external
def add_to_whitelist(account: address):
    # VULNERABILITY: State change without event emission
    assert msg.sender == self.owner, "Not owner"
    self.whitelist[account] = True

@external
def remove_from_whitelist(account: address):
    # VULNERABILITY: State change without event emission
    assert msg.sender == self.owner, "Not owner"
    self.whitelist[account] = False

@external
def safe_transfer_ownership(new_owner: address):
    # SAFE: Has event emission
    assert msg.sender == self.owner, "Not owner"
    old_owner: address = self.owner
    self.owner = new_owner
    log OwnershipTransferred(old_owner, new_owner)
