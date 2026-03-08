# @version ^0.3.7
# Vulnerability: Unsafe raw_call usage without checking return values
# Expected detections: unsafe_raw_call

owner: public(address)
target: public(address)

@external
def __init__(_target: address):
    self.owner = msg.sender
    self.target = _target

@external
def execute_call(data: Bytes[1024]):
    # VULNERABILITY: raw_call without assert — return value ignored
    raw_call(self.target, data)

@external
def execute_with_value(data: Bytes[1024], value: uint256):
    # VULNERABILITY: raw_call with value, no assert
    raw_call(self.target, data, value=value)

@external
def multi_call(targets: DynArray[address, 10], data: DynArray[Bytes[1024], 10]):
    # VULNERABILITY: raw_call in loop without assert
    for i: uint256 in range(10):
        if i >= len(targets):
            break
        raw_call(targets[i], data[i])

@external
def safe_call(data: Bytes[1024]):
    # SAFE: raw_call with assert
    assert raw_call(self.target, data, revert_on_failure=False), "Call failed"
