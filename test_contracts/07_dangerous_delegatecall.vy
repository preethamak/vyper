# @version ^0.3.9
# Vulnerability: Dangerous delegatecall usage
# Expected detections: dangerous_delegatecall

owner: public(address)
implementation: public(address)

@external
def __init__(_impl: address):
    self.owner = msg.sender
    self.implementation = _impl

@external
def upgrade(new_impl: address):
    assert msg.sender == self.owner, "Not owner"
    self.implementation = new_impl

@external
def execute(data: Bytes[1024]):
    # VULNERABILITY: delegatecall without access control
    raw_call(self.implementation, data, is_delegate_call=True)

@external
def execute_arbitrary(target: address, data: Bytes[1024]):
    # VULNERABILITY: delegatecall to arbitrary address
    raw_call(target, data, is_delegate_call=True)

@external
def safe_execute(data: Bytes[1024]):
    # SAFER: delegatecall with access control (lower severity)
    assert msg.sender == self.owner, "Not owner"
    raw_call(self.implementation, data, is_delegate_call=True)
