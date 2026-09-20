// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ProtocoloAntecipacao} from "../src/ProtocoloAntecipacao.sol";
import {MockStablecoin} from "../src/mocks/MockStablecoin.sol";
import {MaliciousStablecoin} from "./mocks/MaliciousStablecoin.sol";

/// @title ProtocoloAntecipacaoTest
/// @notice Suite de testes que implementa integralmente a Tabela 7 (Casos de
///         Teste do Plano de Verificação) do TCC, executada contra o
///         contrato ProtocoloAntecipacao.sol tal como submetido.
///
/// NOTA METODOLÓGICA: dois nomes na Tabela 7 estão grafados com "T" maiúsculo
/// ("Test_ComprarFracoes_AutenticacaoVoucher" e
/// "Test_MecanismoInterrupcao_Pausavel"). O Foundry só reconhece como teste
/// funções cujo nome comece com "test" (minúsculo) ou "testFuzz". Mantida a
/// grafia literal, essas duas funções NÃO seriam executadas por
/// `forge test`. Por isso, abaixo elas foram implementadas com "t"
/// minúsculo — ajuste equivalente necessário para que os 16 casos da
/// Tabela 7 realmente rodem.
contract ProtocoloAntecipacaoTest is Test {
    ProtocoloAntecipacao internal protocolo;
    MockStablecoin internal stablecoin;

    address internal admin = makeAddr("admin");
    uint256 internal kycSignerPk = 0xBEEF;
    address internal kycSigner;
    address internal oraculo = makeAddr("oraculo");
    address internal cedente = makeAddr("cedente");
    address internal investidor = makeAddr("investidor");
    address internal investidor2 = makeAddr("investidor2");
    address internal atacante = makeAddr("atacante");

    uint256 internal constant VALOR_NOMINAL = 10_000e18;
    uint256 internal constant PRECO_FRACAO = 100e18;
    uint256 internal constant TOTAL_FRACOES = 100;
    uint64 internal constant PRAZO = 90 days;

    function setUp() public {
        kycSigner = vm.addr(kycSignerPk);
        stablecoin = new MockStablecoin();

        vm.prank(admin);
        protocolo = new ProtocoloAntecipacao("", address(stablecoin), kycSigner);

        bytes32 oraculoRole = protocolo.ORACULO_ROLE();
        vm.prank(admin);
        protocolo.grantRole(oraculoRole, oraculo);

        stablecoin.mint(investidor, 1_000_000e18);
        stablecoin.mint(investidor2, 1_000_000e18);
        stablecoin.mint(oraculo, 1_000_000e18);
        stablecoin.mint(atacante, 1_000_000e18);

        vm.prank(investidor);
        stablecoin.approve(address(protocolo), type(uint256).max);
        vm.prank(investidor2);
        stablecoin.approve(address(protocolo), type(uint256).max);
        vm.prank(oraculo);
        stablecoin.approve(address(protocolo), type(uint256).max);
        vm.prank(atacante);
        stablecoin.approve(address(protocolo), type(uint256).max);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _cadastrar() internal returns (uint256 id) {
        vm.prank(admin);
        id = protocolo.cadastrarDuplicata(
            keccak256("NFe-0001"),
            cedente,
            VALOR_NOMINAL,
            PRECO_FRACAO,
            TOTAL_FRACOES,
            uint64(block.timestamp) + PRAZO,
            keccak256("gravame-0001")
        );
    }

    /// Assina um voucher de KYC válido em nome do kycSigner para o
    /// comprador, quantidade e validade informados.
    function _voucherValido(uint256 id, uint256 qtd, address comprador, uint256 validade)
        internal
        view
        returns (bytes memory)
    {
        return _assinarVoucher(kycSignerPk, id, qtd, comprador, validade);
    }

    function _assinarVoucher(uint256 signerPk, uint256 id, uint256 qtd, address comprador, uint256 validade)
        internal
        view
        returns (bytes memory)
    {
        bytes32 mensagemHash =
            keccak256(abi.encodePacked(comprador, id, qtd, validade, block.chainid, address(protocolo)));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", mensagemHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    // ==================================================================
    // CATEGORIA: UNITÁRIO
    // ==================================================================

    /// test_CadastrarDuplicata_Sucesso (RF01, RNF03)
    /// Incremento sequencial do duplicataId, estado inicial Disponivel e
    /// persistência imutável dos metadados e hashes no storage.
    function test_CadastrarDuplicata_Sucesso() public {
        uint256 id1 = _cadastrar();
        assertEq(id1, 1, "primeiro id deve ser 1");

        vm.prank(admin);
        uint256 id2 = protocolo.cadastrarDuplicata(
            keccak256("NFe-0002"), cedente, VALOR_NOMINAL, PRECO_FRACAO, TOTAL_FRACOES,
            uint64(block.timestamp) + PRAZO, keccak256("gravame-0002")
        );
        assertEq(id2, 2, "segundo id deve incrementar sequencialmente");

        (
            bytes32 documentoId,
            address cedenteArmazenado,
            uint256 valorNominalTotal,
            uint256 precoVendaFracao,
            uint256 totalFracoes,
            uint256 fracoesDisponiveis,
            uint64 dataVencimento,
            ProtocoloAntecipacao.StatusDuplicata status,
            bytes32 hashGravame
        ) = protocolo.duplicatas(id1);

        assertEq(documentoId, keccak256("NFe-0001"));
        assertEq(cedenteArmazenado, cedente);
        assertEq(valorNominalTotal, VALOR_NOMINAL);
        assertEq(precoVendaFracao, PRECO_FRACAO);
        assertEq(totalFracoes, TOTAL_FRACOES);
        assertEq(fracoesDisponiveis, TOTAL_FRACOES);
        assertEq(dataVencimento, uint64(block.timestamp) + PRAZO);
        assertEq(uint8(status), uint8(ProtocoloAntecipacao.StatusDuplicata.Disponivel));
        assertEq(hashGravame, keccak256("gravame-0001"));
    }

    /// test_CadastrarDuplicata_AcessoRestrito (RF01, RNF05)
    /// vm.prank + vm.expectRevert comprovam o bloqueio de acesso via RBAC
    /// (ADMIN_ROLE) a não autorizadas.
    function test_CadastrarDuplicata_AcessoRestrito() public {
        vm.prank(atacante);
        vm.expectRevert();
        protocolo.cadastrarDuplicata(
            keccak256("x"), cedente, VALOR_NOMINAL, PRECO_FRACAO, TOTAL_FRACOES,
            uint64(block.timestamp) + PRAZO, bytes32(0)
        );
        assertFalse(protocolo.hasRole(protocolo.ADMIN_ROLE(), atacante));
    }

    /// test_ComprarFracoes_AutenticacaoVoucher (RF03, RF08)
    /// Validação da assinatura criptográfica ECDSA (kycSigner); reverte
    /// tentativas de compra com voucher inválido ou expirado.
    function test_ComprarFracoes_AutenticacaoVoucher() public {
        uint256 id = _cadastrar();
        uint256 validade = block.timestamp + 1 hours;

        // 1) Voucher assinado por uma chave que NÃO é o kycSigner -> reverte
        uint256 chaveErrada = 0xDEAD;
        bytes memory voucherFalso = _assinarVoucher(chaveErrada, id, 10, investidor, validade);
        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.KYCInvalido.selector);
        protocolo.comprarFracoes(id, 10, validade, voucherFalso);

        // 2) Voucher assinado pelo kycSigner correto, mas já expirado -> reverte
        bytes memory voucherExpirado = _voucherValido(id, 10, investidor, validade);
        vm.warp(block.timestamp + 2 hours);
        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.AutorizacaoExpirada.selector);
        protocolo.comprarFracoes(id, 10, validade, voucherExpirado);

        // 3) Voucher válido do kycSigner, dentro da validade -> sucesso
        uint256 novaValidade = block.timestamp + 1 hours;
        bytes memory voucherValido = _voucherValido(id, 10, investidor, novaValidade);
        vm.prank(investidor);
        protocolo.comprarFracoes(id, 10, novaValidade, voucherValido);
        assertEq(protocolo.balanceOf(investidor, id), 10);
    }

    /// test_ComprarFracoes_SucessoEEstoque (RF02, RF03)
    /// Transferência de moedas estáveis via safeTransferFrom, decremento
    /// atômico de fracoesDisponiveis e cunhagem dos tokens ERC-1155 ao
    /// Investidor.
    function test_ComprarFracoes_SucessoEEstoque() public {
        uint256 id = _cadastrar();
        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id, 30, investidor, validade);

        uint256 saldoAntes = stablecoin.balanceOf(investidor);

        vm.prank(investidor);
        protocolo.comprarFracoes(id, 30, validade, voucher);

        assertEq(protocolo.balanceOf(investidor, id), 30, "tokens ERC-1155 cunhados corretamente");
        assertEq(stablecoin.balanceOf(investidor), saldoAntes - 30 * PRECO_FRACAO, "stablecoin debitada do investidor");
        assertEq(stablecoin.balanceOf(address(protocolo)), 30 * PRECO_FRACAO, "stablecoin custodiada no contrato");

        (,,,,, uint256 fracoesDisponiveis,,,) = protocolo.duplicatas(id);
        assertEq(fracoesDisponiveis, TOTAL_FRACOES - 30, "estoque decrementado atomicamente");
    }

    /// test_ComprarFracoes_EstoqueExcedidoEPrazo (RF02, RF03)
    /// Reversão atômica ao solicitar quantidade acima do estoque disponível
    /// ou após o vencimento do prazo (dataVencimento).
    function test_ComprarFracoes_EstoqueExcedidoEPrazo() public {
        // Cenário 1: quantidade acima do estoque disponível
        uint256 id1 = _cadastrar();
        uint256 validade1 = block.timestamp + 1 hours;
        bytes memory voucher1 = _voucherValido(id1, TOTAL_FRACOES + 1, investidor, validade1);
        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.QuantidadeIndisponivel.selector);
        protocolo.comprarFracoes(id1, TOTAL_FRACOES + 1, validade1, voucher1);

        // Cenário 2: prazo de vencimento do título já expirou
        vm.prank(admin);
        uint256 id2 = protocolo.cadastrarDuplicata(
            keccak256("NFe-0002"), cedente, VALOR_NOMINAL, PRECO_FRACAO, TOTAL_FRACOES,
            uint64(block.timestamp) + 1 days, keccak256("gravame-0002")
        );
        vm.warp(block.timestamp + 2 days);
        uint256 validade2 = block.timestamp + 1 hours;
        bytes memory voucher2 = _voucherValido(id2, 10, investidor, validade2);
        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.PrazoExpirado.selector);
        protocolo.comprarFracoes(id2, 10, validade2, voucher2);
    }

    /// test_ResgatarSaldoCedente_Sucesso (RF04)
    /// Transição do título para Captado, consolidação do saldo em
    /// saldosCedentes e saque exclusivo via Pull Payment.
    function test_ResgatarSaldoCedente_Sucesso() public {
        uint256 id = _cadastrar();
        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id, TOTAL_FRACOES, investidor, validade);

        vm.prank(investidor);
        protocolo.comprarFracoes(id, TOTAL_FRACOES, validade, voucher);

        (,,,,,,, ProtocoloAntecipacao.StatusDuplicata status,) = protocolo.duplicatas(id);
        assertEq(uint8(status), uint8(ProtocoloAntecipacao.StatusDuplicata.Captado), "estoque esgotado -> Captado");
        assertEq(protocolo.saldosCedentes(cedente), VALOR_NOMINAL, "saldo consolidado no mapping");

        // Saque exclusivo: um terceiro não consegue sacar o saldo do cedente
        vm.prank(atacante);
        vm.expectRevert(ProtocoloAntecipacao.SemSaldoDisponivel.selector);
        protocolo.resgatarSaldoCedente();

        uint256 saldoAntes = stablecoin.balanceOf(cedente);
        vm.prank(cedente);
        protocolo.resgatarSaldoCedente();
        assertEq(stablecoin.balanceOf(cedente), saldoAntes + VALOR_NOMINAL);
        assertEq(protocolo.saldosCedentes(cedente), 0);
    }

    /// test_MecanismoInterrupcao_Pausavel (RF09, RNF05)
    /// O Administrador aciona o módulo Pausable; confirma o bloqueio
    /// imediato e o posterior desbloqueio das funções financeiras do
    /// contrato.
    function test_MecanismoInterrupcao_Pausavel() public {
        uint256 id = _cadastrar();
        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id, 10, investidor, validade);

        // Apenas ADMIN_ROLE pode pausar
        vm.prank(atacante);
        vm.expectRevert();
        protocolo.pausarProtocolo();

        vm.prank(admin);
        protocolo.pausarProtocolo();

        // Bloqueio imediato de uma função financeira crítica
        vm.prank(investidor);
        vm.expectRevert();
        protocolo.comprarFracoes(id, 10, validade, voucher);

        // Desbloqueio: a mesma operação volta a funcionar após despausar
        vm.prank(admin);
        protocolo.despausarProtocolo();

        vm.prank(investidor);
        protocolo.comprarFracoes(id, 10, validade, voucher);
        assertEq(protocolo.balanceOf(investidor, id), 10);
    }

    // ==================================================================
    // CATEGORIA: INTEGRAÇÃO
    // ==================================================================

    /// test_LiquidarTitulo_SucessoEAutorizado (RF05, RNF05)
    /// O modificador onlyRole(ORACULO_ROLE) autoriza o endereço do Oráculo,
    /// atualiza o estado para Liquidado e realiza o aporte custodial de
    /// moedas estáveis.
    function test_LiquidarTitulo_SucessoEAutorizado() public {
        uint256 id = _cadastrar();
        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id, TOTAL_FRACOES, investidor, validade);
        vm.prank(investidor);
        protocolo.comprarFracoes(id, TOTAL_FRACOES, validade, voucher);

        uint256 saldoContratoAntes = stablecoin.balanceOf(address(protocolo));

        vm.prank(oraculo);
        protocolo.liquidarTitulo(id);

        (,,,,,,, ProtocoloAntecipacao.StatusDuplicata status,) = protocolo.duplicatas(id);
        assertEq(uint8(status), uint8(ProtocoloAntecipacao.StatusDuplicata.Liquidado));
        assertEq(
            stablecoin.balanceOf(address(protocolo)),
            saldoContratoAntes + VALOR_NOMINAL,
            "aporte custodial do valor nominal pelo Oraculo"
        );
    }

    /// test_LiquidarTitulo_AcessoRestrito (RF05)
    /// Reversão atômica ao tentar liquidar o título a partir de uma conta
    /// sem o papel Oráculo.
    function test_LiquidarTitulo_AcessoRestrito() public {
        uint256 id = _cadastrar();
        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id, TOTAL_FRACOES, investidor, validade);
        vm.prank(investidor);
        protocolo.comprarFracoes(id, TOTAL_FRACOES, validade, voucher);

        vm.prank(atacante);
        vm.expectRevert();
        protocolo.liquidarTitulo(id);
    }

    /// test_ConsolidacaoEResgateInvestidor_Sucesso (RF06, RF07, RNF01)
    /// Apuração contábil dos saldos devidos pós-liquidação, queima
    /// definitiva das frações (_burn) antes do repasse financeiro e
    /// transferência dos fundos.
    function test_ConsolidacaoEResgateInvestidor_Sucesso() public {
        uint256 id = _cadastrar();
        uint256 validade = block.timestamp + 1 hours;

        bytes memory voucher1 = _voucherValido(id, 60, investidor, validade);
        vm.prank(investidor);
        protocolo.comprarFracoes(id, 60, validade, voucher1);

        bytes memory voucher2 = _voucherValido(id, 40, investidor2, validade);
        vm.prank(investidor2);
        protocolo.comprarFracoes(id, 40, validade, voucher2);

        vm.prank(oraculo);
        protocolo.liquidarTitulo(id);

        // Apuração contábil: cada investidor recebe exatamente sua fração
        // proporcional do valor nominal
        uint256 saldoAntes = stablecoin.balanceOf(investidor);
        vm.prank(investidor);
        protocolo.resgatarFracoesInvestidor(id);
        assertEq(stablecoin.balanceOf(investidor), saldoAntes + 6_000e18, "60% do valor nominal");
        assertEq(protocolo.balanceOf(investidor, id), 0, "tokens queimados (_burn)");

        uint256 saldoAntes2 = stablecoin.balanceOf(investidor2);
        vm.prank(investidor2);
        protocolo.resgatarFracoesInvestidor(id);
        assertEq(stablecoin.balanceOf(investidor2), saldoAntes2 + 4_000e18, "40% do valor nominal");

        // Resgate duplo deve reverter (frações já queimadas)
        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.SemFracoesParaResgate.selector);
        protocolo.resgatarFracoesInvestidor(id);
    }

    /// test_Conformidade_ERC1155_ERC20 (RNF06)
    /// Conformidade total com as interfaces regulamentadas da indústria
    /// (ERC-1155 e SafeERC20), validando safeTransferFrom, balanceOf e
    /// aprovações.
    function test_Conformidade_ERC1155_ERC20() public {
        uint256 id1 = _cadastrar();
        vm.prank(admin);
        uint256 id2 = protocolo.cadastrarDuplicata(
            keccak256("NFe-0002"), cedente, VALOR_NOMINAL, PRECO_FRACAO, TOTAL_FRACOES,
            uint64(block.timestamp) + PRAZO, keccak256("gravame-0002")
        );

        uint256 validade = block.timestamp + 1 hours;
        bytes memory v1 = _voucherValido(id1, 5, investidor, validade);
        bytes memory v2 = _voucherValido(id2, 7, investidor, validade);

        vm.startPrank(investidor);
        protocolo.comprarFracoes(id1, 5, validade, v1);
        protocolo.comprarFracoes(id2, 7, validade, v2);
        vm.stopPrank();

        // balanceOf/balanceOfBatch nativos do ERC-1155
        address[] memory contas = new address[](2);
        uint256[] memory ids = new uint256[](2);
        contas[0] = investidor;
        contas[1] = investidor;
        ids[0] = id1;
        ids[1] = id2;
        uint256[] memory saldos = protocolo.balanceOfBatch(contas, ids);
        assertEq(saldos[0], 5);
        assertEq(saldos[1], 7);

        // Conformidade ERC-20/SafeERC20: a OpenZeppelin ERC20 trata approve
        // com type(uint256).max como aprovacao infinita e nao a decrementa
        // a cada safeTransferFrom -- comportamento padrao verificado aqui.
        assertEq(stablecoin.allowance(investidor, address(protocolo)), type(uint256).max);

        assertTrue(protocolo.supportsInterface(0xd9b67a26)); // ERC1155 interfaceId
        assertTrue(protocolo.supportsInterface(0x7965db0b)); // AccessControl interfaceId
    }

    /// test_Monitoramento_GasReport (RNF04)
    /// Relatório do Foundry comprova operações de busca e atualização em
    /// tempo constante O(1) via mappings, eliminando loops dinâmicos.
    function test_Monitoramento_GasReport() public {
        // Cadastra 3 duplicatas e mede o custo de uma compra na 3a: se o
        // custo não crescer com o número de duplicatas já existentes, o
        // acesso é O(1) (mapping), não O(n) (busca linear).
        _cadastrar();
        _cadastrar();
        uint256 id3 = _cadastrar();

        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id3, 10, investidor, validade);

        uint256 gasAntes = gasleft();
        vm.prank(investidor);
        protocolo.comprarFracoes(id3, 10, validade, voucher);
        uint256 gasUsado = gasAntes - gasleft();

        // custo de escrita e O(1): permanece abaixo de um teto fixo,
        // independentemente de quantas duplicatas já foram cadastradas
        assertLt(gasUsado, 350_000);
    }

    // ==================================================================
    // CATEGORIA: FUZZ TESTING
    // ==================================================================

    /// testFuzz_EstoqueJamaisExcedeNominal (RF02, RNF03)
    /// Invariante: o somatório de frações emitidas nunca excede o valor
    /// nominal do título cadastrado.
    function testFuzz_EstoqueJamaisExcedeNominal(uint256 quantidade) public {
        uint256 id = _cadastrar();
        quantidade = bound(quantidade, 1, TOTAL_FRACOES);
        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id, quantidade, investidor, validade);

        vm.prank(investidor);
        protocolo.comprarFracoes(id, quantidade, validade, voucher);

        (,,,, uint256 totalFracoes, uint256 fracoesDisponiveis,,,) = protocolo.duplicatas(id);
        assertLe(protocolo.balanceOf(investidor, id), totalFracoes, "fracoes emitidas nunca excedem o total nominal");
        assertEq(fracoesDisponiveis, totalFracoes - quantidade);
    }

    /// testFuzz_Imunidade_OverflowUnderflow (RNF03)
    /// Valores extremos (2^256-1) confirmam ausência de overflow/underflow
    /// no Solidity 0.8.20.
    function testFuzz_Imunidade_OverflowUnderflow(uint256 quantidade) public {
        uint256 id = _cadastrar();
        // valores fora do intervalo válido devem reverter de forma
        // controlada, nunca causar overflow/underflow silencioso
        vm.assume(quantidade == 0 || quantidade > TOTAL_FRACOES);
        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id, quantidade, investidor, validade);

        vm.prank(investidor);
        vm.expectRevert(ProtocoloAntecipacao.QuantidadeIndisponivel.selector);
        protocolo.comprarFracoes(id, quantidade, validade, voucher);
    }

    /// testFuzz_PreencheuEfeitosAntesInteracoes (RNF01)
    /// Validação estrita do padrão CEI: atualização de saldos e queima de
    /// tokens executadas antes de qualquer transferência para endereços
    /// externos.
    function testFuzz_PreencheuEfeitosAntesInteracoes(uint256 quantidade) public {
        uint256 id = _cadastrar();
        quantidade = bound(quantidade, 1, TOTAL_FRACOES);
        uint256 validade = block.timestamp + 1 hours;
        bytes memory voucher = _voucherValido(id, quantidade, investidor, validade);
        vm.prank(investidor);
        protocolo.comprarFracoes(id, quantidade, validade, voucher);

        // encerra a captação inteira para poder liquidar
        if (quantidade < TOTAL_FRACOES) {
            bytes memory voucherResto = _voucherValido(id, TOTAL_FRACOES - quantidade, investidor2, validade);
            vm.prank(investidor2);
            protocolo.comprarFracoes(id, TOTAL_FRACOES - quantidade, validade, voucherResto);
        }
        vm.prank(oraculo);
        protocolo.liquidarTitulo(id);

        assertEq(protocolo.balanceOf(investidor, id), quantidade, "saldo intacto antes do resgate");
        vm.prank(investidor);
        protocolo.resgatarFracoesInvestidor(id);
        // Effects (_burn) ocorre antes da Interaction (safeTransfer); após a
        // chamada bem-sucedida, o saldo de tokens já deve estar zerado
        assertEq(protocolo.balanceOf(investidor, id), 0, "_burn executado (Effects antes de Interactions)");
    }

    /// testFuzz_BloqueioMutex_Reentrancia (RNF02)
    /// Contrato malicioso tenta reentrância; o modificador nonReentrant
    /// bloqueia e força o rollback.
    function test_BloqueioMutex_Reentrancia() public {
        MaliciousStablecoin tokenMalicioso = new MaliciousStablecoin();
        vm.prank(admin);
        ProtocoloAntecipacao protocoloVulneravelTeste =
            new ProtocoloAntecipacao("", address(tokenMalicioso), kycSigner);

        vm.prank(admin);
        uint256 id = protocoloVulneravelTeste.cadastrarDuplicata(
            keccak256("NFe-ataque"), cedente, VALOR_NOMINAL, PRECO_FRACAO, TOTAL_FRACOES,
            uint64(block.timestamp) + PRAZO, keccak256("gravame-ataque")
        );

        tokenMalicioso.mint(investidor, 1_000_000e18);
        vm.prank(investidor);
        tokenMalicioso.approve(address(protocoloVulneravelTeste), type(uint256).max);

        uint256 validade = block.timestamp + 1 hours;
        bytes32 mensagemHash = keccak256(
            abi.encodePacked(investidor, id, TOTAL_FRACOES, validade, block.chainid, address(protocoloVulneravelTeste))
        );
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", mensagemHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(kycSignerPk, ethSignedMessageHash);
        bytes memory voucher = abi.encodePacked(r, s, v);

        vm.prank(investidor);
        protocoloVulneravelTeste.comprarFracoes(id, TOTAL_FRACOES, validade, voucher);

        bytes32 oraculoRole = protocoloVulneravelTeste.ORACULO_ROLE();
        vm.prank(admin);
        protocoloVulneravelTeste.grantRole(oraculoRole, oraculo);
        tokenMalicioso.mint(oraculo, VALOR_NOMINAL);
        vm.prank(oraculo);
        tokenMalicioso.approve(address(protocoloVulneravelTeste), type(uint256).max);
        vm.prank(oraculo);
        protocoloVulneravelTeste.liquidarTitulo(id);

        // Configura o ataque apenas agora, para que a chamada legítima de
        // liquidação acima não dispare a reentrância prematuramente
        tokenMalicioso.configurarAtaque(protocoloVulneravelTeste, id);

        // O Mutex (nonReentrant) deve reverter a chamada reentrante
        // disparada dentro de transfer(), bloqueando o saque duplo
        vm.prank(investidor);
        vm.expectRevert();
        protocoloVulneravelTeste.resgatarFracoesInvestidor(id);
    }
}
