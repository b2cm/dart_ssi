pragma solidity ^0.7.5;

contract RevocationRegistry {
    
address public owner;
uint public deployed;

event RevokedEvent(address indexed credential);

modifier onlyOwner(){
    require(msg.sender == owner, 'no owner');
    _;
}

constructor(){
    owner = msg.sender;
    deployed = block.number;
}

function revoke(address _credential) public onlyOwner {
    emit RevokedEvent(_credential);
}

function changeOwner(address _newOwner) public  onlyOwner{
    owner = _newOwner;
}
}
