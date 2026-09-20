// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice Mock de stablecoin (ex.: BRZ, USDC) usado exclusivamente nos testes do
///         Protocolo de Antecipacao. Permite mint livre para simular liquidez dos
///         atores (Investidor, Sacado, Plataforma) nos cenarios de teste.
contract MockStablecoin is ERC20 {
    constructor() ERC20("Mock Stablecoin", "mUSD") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
