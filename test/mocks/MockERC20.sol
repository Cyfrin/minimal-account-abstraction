// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    uint256 public constant AMOUNT = 1e18;

    constructor() ERC20("Mock ERC20", "MERC") { }

    function mint() public {
        _mint(msg.sender, AMOUNT);
    }
}
