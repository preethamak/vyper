# @version ^0.3.9
# Vulnerability: Unprotected selfdestruct / kill
# Expected detections: unprotected_selfdestruct

owner: public(address)
initialized: public(bool)

@external
def __init__():
    self.owner = msg.sender
    self.initialized = True

@external
def emergency_destroy():
    # VULNERABILITY: No access control on selfdestruct
    selfdestruct(msg.sender)

@external
def kill_contract():
    # VULNERABILITY: No access control on selfdestruct
    selfdestruct(self.owner)

@external
def safe_destroy():
    # SAFE: Has ownership check
    assert msg.sender == self.owner, "Not owner"
    selfdestruct(self.owner)
