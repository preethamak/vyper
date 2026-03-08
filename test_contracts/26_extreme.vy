# @version ^0.3.3

struct User:
    balance: uint256
    active: bool

users: HashMap[address, User]

@external
@payable
def deposit():
    self.users[msg.sender].balance += msg.value
    self.users[msg.sender].active = True

@external
def withdraw():
    u: User = self.users[msg.sender]

    if u.active:
        raw_call(msg.sender, b"", value=u.balance)

    self.users[msg.sender].balance = 0