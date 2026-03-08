# @version ^0.2.8

balances: public(HashMap[address, uint256])

@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value

@external
def withdraw():
    amount: uint256 = self.balances[msg.sender]

    if amount > 0:
        raw_call(
            msg.sender,
            b"",
            value=amount
        )

        self.balances[msg.sender] = 0