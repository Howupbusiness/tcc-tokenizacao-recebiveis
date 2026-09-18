// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {ProtocoloAntecipacao} from "../src/ProtocoloAntecipacao.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// Mock simples de Stablecoin ERC-20 para servir como TOKEN_LIQUIDADOR nos testes
contract MockStablecoin is ERC20 {
    constructor() ERC20("Mock BRL Stablecoin", "mBRL") {
        _mint(msg.sender, 1000000 * 10**18);
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract ProtocoloAntecipacaoTest is Test {
    ProtocoloAntecipacao public protocolo;
    MockStablecoin public tokenLiquidador;

    // Contas de teste
    address public admin = address(0x1);
    address public oraculo = address(0x2);
    address public cedente = address(0x3);
    address public investidor = address(0x4);
    
    // Chave privada e endereço do assinante do KYC (Simulando o Back-end Web2)
    uint256 public kycPrivateKey = 0xA11CE;
    address public kycSigner;

    // Parâmetros padronizados para uma duplicata de teste
    bytes32 public docId = keccak256("NF-12345");
    bytes32 public gravame = keccak256("REGISTRO-CERC-01");
    uint256 public valorTotal = 10000 * 10**18; // R$ 10.000,00
    uint256 public precoFracao = 10 * 10**18;   // R$ 10,00 por fração
    uint256 public totalFracoes = 1000;
    uint64 public vencimento;

    function setUp() public {
        kycSigner = vm.addr(kycPrivateKey);
        vencimento = uint64(block.timestamp + 90 days);

        // Deploy dos contratos em ambiente de teste
        vm.startPrank(admin);
        tokenLiquidador = new MockStablecoin();
        protocolo = new ProtocoloAntecipacao("https://howup.com{id}", address(tokenLiquidador), kycSigner);
        
        // Atribui o papel de Oráculo à conta correspondente
        protocolo.grantRole(protocolo.ORACULO_ROLE(), oraculo);
        vm.stopPrank();

        // Distribui fundos iniciais de moedas estáveis para o investidor e oráculo
        tokenLiquidador.mint(investidor, 50000 * 10**18);
        tokenLiquidador.mint(oraculo, 50000 * 10**18);

        vm.prank(investidor);
        tokenLiquidador.approve(address(protocolo), type(uint256).max);
        
        vm.prank(oraculo);
        tokenLiquidador.approve(address(protocolo), type(uint256).max);
    }

    // Helper para assinar os vouchers de KYC criptograficamente (ECDSA)
    function _gerarAssinaturaKYC(address user, uint256 id, uint256 qtd, uint256 val) internal view returns (bytes memory) {
        bytes32 msgHash = keccak256(abi.encodePacked(user, id, qtd, val, block.chainid, address(protocolo)));
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (v, r, s) = vm.sign(kycPrivateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }
    uint8 private v; bytes32 private r; bytes32 private s;

    // ==========================================
    // SEÇÃO DE TESTES UNITÁRIOS (Tabela 7)
    // ==========================================

    function test_CadastrarDuplicata_Sucesso() public {
        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);
        
        assertEq(id, 1);
        (bytes32 dId, address ced, uint256 val, , , , uint64 venc, ProtocoloAntecipacao.StatusDuplicata status, ) = protocolo.duplicatas(id);
        assertEq(dId, docId);
        assertEq(ced, cedente);
        assertEq(val, valorTotal);
        assertEq(venc, vencimento);
        assertTrue(status == ProtocoloAntecipacao.StatusDuplicata.Disponivel);
    }

    function test_CadastrarDuplicata_AcessoRestrito() public {
        vm.prank(investidor); // Conta sem privilégios de ADMIN_ROLE
        vm.expectRevert();
        protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);
    }

    function test_ComprarFracoes_Sucesso() public {
        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);

        uint256 qtdCompra = 100;
        uint256 validadeVoucher = block.timestamp + 1 hours;
        bytes memory sig = _gerarAssinaturaKYC(investidor, id, qtdCompra, validadeVoucher);

        uint256 saldoInicialUser = tokenLiquidador.balanceOf(investidor);

        vm.prank(investidor);
        protocolo.comprarFracoes(id, qtdCompra, validadeVoucher, sig);

        assertEq(protocolo.balanceOf(investidor, id), qtdCompra);
        assertEq(tokenLiquidador.balanceOf(investidor), saldoInicialUser - (qtdCompra * precoFracao));
    }

    function test_ComprarFracoes_PrazoExpirado() public {
        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);

        uint256 qtdCompra = 50;
        uint256 validadeVoucher = block.timestamp + 1 hours;
        bytes memory sig = _gerarAssinaturaKYC(investidor, id, qtdCompra, validadeVoucher);

        // Avança o relógio da blockchain para além do vencimento do título
        vm.warp(vencimento + 1);

        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.PrazoExpirado.selector);
        protocolo.comprarFracoes(id, qtdCompra, validadeVoucher, sig);
    }

    function test_ComprarFracoes_EstoqueExcedido() public {
        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);

        uint256 qtdInvalida = totalFracoes + 1; // Solicita mais do que o total criado
        uint256 validadeVoucher = block.timestamp + 1 hours;
        bytes memory sig = _gerarAssinaturaKYC(investidor, id, qtdInvalida, validadeVoucher);

        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.QuantidadeIndisponivel.selector);
        protocolo.comprarFracoes(id, qtdInvalida, validadeVoucher, sig);
    }

    function test_EncerramentoCaptacao_Bloqueio() public {
        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);

        // Adquire o estoque total de frações de uma só vez
        uint256 validadeVoucher = block.timestamp + 1 hours;
        bytes memory sig = _gerarAssinaturaKYC(investidor, id, totalFracoes, validadeVoucher);

        vm.prank(investidor);
        protocolo.comprarFracoes(id, totalFracoes, validadeVoucher, sig);

        (, , , , , , , ProtocoloAntecipacao.StatusDuplicata status, ) = protocolo.duplicatas(id);
        assertTrue(status == ProtocoloAntecipacao.StatusDuplicata.Captado);
        assertEq(protocolo.saldosCedentes(cedente), totalFracoes * precoFracao);
    }

    // ==========================================
    // SEÇÃO DE TESTES DE INTEGRAÇÃO & MOCKS
    // ==========================================

    function test_LiquidarTitulo_SucessoOraculo() public {
        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);

        bytes memory sig = _gerarAssinaturaKYC(investidor, id, totalFracoes, block.timestamp + 1 hours);
        vm.prank(investidor);
        protocolo.comprarFracoes(id, totalFracoes, block.timestamp + 1 hours, sig);

        vm.prank(oraculo);
        protocolo.liquidarTitulo(id);

        (, , , , , , , ProtocoloAntecipacao.StatusDuplicata status, ) = protocolo.duplicatas(id);
        assertTrue(status == ProtocoloAntecipacao.StatusDuplicata.Liquidado);
    }

    function test_LiquidarTitulo_AcessoRestrito() public {
        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);

        bytes memory sig = _gerarAssinaturaKYC(investidor, id, totalFracoes, block.timestamp + 1 hours);
        vm.prank(investidor);
        protocolo.comprarFracoes(id, totalFracoes, block.timestamp + 1 hours, sig);

        vm.prank(investidor); // Tenta liquidar usando uma conta sem o papel de ORACULO_ROLE
        vm.expectRevert();
        protocolo.liquidarTitulo(id);
    }

    function test_ConsolidacaoDireitos_AposLiquidar() public {
        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);

        bytes memory sig = _gerarAssinaturaKYC(investidor, id, totalFracoes, block.timestamp + 1 hours);
        vm.prank(investidor);
        protocolo.comprarFracoes(id, totalFracoes, block.timestamp + 1 hours, sig);

        vm.prank(oraculo);
        protocolo.liquidarTitulo(id);

        uint256 saldoAntesResgate = tokenLiquidador.balanceOf(investidor);
        
        vm.prank(investidor);
        protocolo.resgatarFracoesInvestidor(id);

        assertEq(tokenLiquidador.balanceOf(investidor), saldoAntesResgate + valorTotal);
    }

    // ==========================================
    // SEÇÃO DE FUZZ TESTING (Testes de Propriedade)
    // ==========================================

    function testFuzz_EstoqueJamaisExcedeNominal(uint256 quantidadeAleatoria) public {
        // Filtra a entrada do Fuzz para valores que estouram o estoque lógico criado
        vm.assume(quantidadeAleatoria > totalFracoes && quantidadeAleatoria < 100000);

        vm.prank(admin);
        uint256 id = protocolo.cadastrarDuplicata(docId, cedente, valorTotal, precoFracao, totalFracoes, vencimento, gravame);

        uint256 validadeVoucher = block.timestamp + 1 hours;
        bytes memory sig = _gerarAssinaturaKYC(investidor, id, quantidadeAleatoria, validadeVoucher);

        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.QuantidadeIndisponivel.selector);
        protocolo.comprarFracoes(id, quantidadeAleatoria, validadeVoucher, sig);
    }
}

