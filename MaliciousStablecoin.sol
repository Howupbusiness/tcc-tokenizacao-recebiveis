// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ProtocoloAntecipacao} from "../../src/ProtocoloAntecipacao.sol";

/// @notice Stablecoin maliciosa usada exclusivamente para provar que o Mutex
///         (nonReentrant) do ProtocoloAntecipacao bloqueia tentativas de
///         reentrância durante a Interaction de resgate (transfer). Simula um
///         token com callback que tenta chamar novamente
///         resgatarFracoesInvestidor antes que a primeira chamada retorne.
contract MaliciousStablecoin is ERC20 {
    ProtocoloAntecipacao public alvo;
    uint256 public duplicataIdAlvo;
    bool internal atacando;

    constructor() ERC20("Malicious Stablecoin", "mXSS") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function configurarAtaque(ProtocoloAntecipacao _alvo, uint256 _duplicataId) external {
        alvo = _alvo;
        duplicataIdAlvo = _duplicataId;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        bool ok = super.transfer(to, amount);
        if (!atacando && address(alvo) != address(0)) {
            atacando = true;
            // Tentativa de reentrancia: se o Mutex nao estivesse ativo, esta
            // chamada sacaria o mesmo saldo uma segunda vez antes do retorno
            // da chamada externa original.
            alvo.resgatarFracoesInvestidor(duplicataIdAlvo);
        }
        return ok;
    }
}
