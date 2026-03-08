# @version ^0.3.9
# Vulnerability: Unprotected state changes to critical variables
# Expected detections: unprotected_state_change

owner: public(address)
admin: public(address)
treasury: public(address)
fee_recipient: public(address)
max_deposit: public(uint256)
withdrawal_limit: public(uint256)
is_paused: public(bool)

@external
def __init__():
    self.owner = msg.sender
    self.admin = msg.sender
    self.treasury = msg.sender
    self.fee_recipient = msg.sender
    self.max_deposit = 100 * 10 ** 18
    self.withdrawal_limit = 50 * 10 ** 18
    self.is_paused = False

@external
def set_owner(new_owner: address):
    # VULNERABILITY: No msg.sender check — anyone can take ownership
    self.owner = new_owner

@external
def set_admin(new_admin: address):
    # VULNERABILITY: No msg.sender check
    self.admin = new_admin

@external
def set_treasury(new_treasury: address):
    # VULNERABILITY: No msg.sender check
    self.treasury = new_treasury

@external
def set_fee_recipient(new_recipient: address):
    # VULNERABILITY: No msg.sender check
    self.fee_recipient = new_recipient

@external
def set_max_deposit(amount: uint256):
    # VULNERABILITY: No msg.sender check
    self.max_deposit = amount

@external
def pause():
    # VULNERABILITY: No msg.sender check
    self.is_paused = True

@external
def unpause():
    # VULNERABILITY: No msg.sender check
    self.is_paused = False

@external
def safe_set_owner(new_owner: address):
    # SAFE: Has ownership check
    assert msg.sender == self.owner, "Not owner"
    self.owner = new_owner
