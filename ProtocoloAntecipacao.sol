// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title ProtocoloAntecipacao
 * @dev Contrato mestre para cadastramento, fracionamento (ERC-1155),
 * liquidação em Stablecoin ERC-20 (com SafeERC20) e saque de duplicatas comerciais tokenizadas (RWA).
 */
contract ProtocoloAntecipacao is ERC1155, AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    // Definição de Papéis (RBAC)
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ORACULO_ROLE = keccak256("ORACULO_ROLE");

    // Instância Imutável da Stablecoin ERC-20 (BRLA / BRZ / Mock)
    IERC20 public immutable TOKEN_LIQUIDADOR;

    // Endereço público do Back-end autorizado a assinar os vouchers de KYC
    address public kycSigner;

    // Maquina de Estados da Duplicata
    enum StatusDuplicata {
        Inexistente, // 0: O ID não foi cadastrado ainda (Valor padrão do Solidity)
        Disponivel, // 1: Captação aberta
        Captado, // 2: Recursos integralmente subscritos
        Liquidado, // 3: Título quitado pelo devedor
        EmAtraso // 4: Inadimplente pós-vencimento
    }

    // Custom Errors (Otimização de Gas)
    error CedenteInvalido();
    error ValorNominalZerado();
    error FracoesZeradas();
    error PrecoFracaoInvalido();
    error VencimentoInvalido();
    error CaptacaoNaoDisponivel();
    error PrazoExpirado();
    error QuantidadeIndisponivel();
    error TituloNaoCaptado();
    error TituloNaoLiquidado();
    error SemFracoesParaResgate();
    error SemSaldoDisponivel();
    error EnderecoInvalido();
    error KYCInvalido();
    error AutorizacaoExpirada();

    // Estrutura de dados da Duplicata-Mãe
    struct Duplicata {
        bytes32 documentoId;
        address cedente;
        uint256 valorNominalTotal;
        uint256 precoVendaFracao;
        uint256 totalFracoes;
        uint256 fracoesDisponiveis;
        uint64 dataVencimento;
        StatusDuplicata statusDuplicata;
        bytes32 hashGravame;
    }

    // Contador sequencial de IDs de duplicatas
    uint256 public proximoDuplicataId = 1;

    // Mapeamentos de Persistência (Storage O(1))
    mapping(uint256 => Duplicata) public duplicatas;
    mapping(address => uint256) public saldosCedentes;

    // Eventos do Sistema
    event DuplicataCadastrada(uint256 indexed duplicataId, bytes32 indexed documentoId, address indexed cedente);
    event FracoesAdquiridas(uint256 indexed duplicataId, address indexed investidor, uint256 quantidade);
    event CaptacaoEncerrada(uint256 indexed duplicataId, uint256 totalCaptado);
    event TituloLiquidado(uint256 indexed duplicataId);
    event FracoesResgatadas(uint256 indexed duplicataId, address indexed investidor, uint256 valor);
    event SaldoResgatado(address indexed cedente, uint256 valor);

    constructor(string memory uri_, address _tokenLiquidador, address _kycSigner) ERC1155(uri_) {
        if (_tokenLiquidador == address(0) || _kycSigner == address(0)) revert EnderecoInvalido();

        // Registra os endereços da Stablecoin ERC-20 (tokenLiquidador) e da carteira do back-end/Servidor (kycSigner)
        TOKEN_LIQUIDADOR = IERC20(_tokenLiquidador);
        kycSigner = _kycSigner;

        // Registra o endereço do Administrador/Deployer
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Permite ao Admin pausar/despausar o protocolo em emergências
     */
    function pausarProtocolo() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    function despausarProtocolo() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Registra uma nova duplicata-mãe no protocolo (RF01)
     */
    function cadastrarDuplicata(
        bytes32 _documentoId,
        address _cedente,
        uint256 _valorNominalTotal,
        uint256 _precoVendaFracao,
        uint256 _totalFracoes,
        uint64 _dataVencimento,
        bytes32 _hashGravame
    ) external onlyRole(ADMIN_ROLE) returns (uint256 duplicataId) {
        if (_cedente == address(0)) revert CedenteInvalido();
        if (_valorNominalTotal == 0) revert ValorNominalZerado();
        if (_totalFracoes == 0) revert FracoesZeradas();
        if (_precoVendaFracao == 0) revert PrecoFracaoInvalido();
        if (_dataVencimento <= block.timestamp) revert VencimentoInvalido();

        duplicataId = proximoDuplicataId++;

        duplicatas[duplicataId] = Duplicata({
            documentoId: _documentoId,
            cedente: _cedente,
            valorNominalTotal: _valorNominalTotal,
            precoVendaFracao: _precoVendaFracao,
            totalFracoes: _totalFracoes,
            fracoesDisponiveis: _totalFracoes,
            dataVencimento: _dataVencimento,
            statusDuplicata: StatusDuplicata.Disponivel,
            hashGravame: _hashGravame
        });

        emit DuplicataCadastrada(duplicataId, _documentoId, _cedente);
    }

    /**
     * @notice Permite a aquisição de frações de um título disponível (RF02, RF03, RF04)
     */
    function comprarFracoes(
        uint256 _duplicataId,
        uint256 _quantidade,
        uint256 _validade, // Timestamp limite de validade da autorização
        bytes calldata _assinatura // Assinatura digital gerada pelo Back-end
    )
        external
        nonReentrant
        whenNotPaused
    {
        // Validação de expiração da permissão
        if (block.timestamp > _validade) revert AutorizacaoExpirada();

        // Reconstrução do hash da mensagem assinada off-chain
        bytes32 mensagemHash =
            keccak256(abi.encodePacked(msg.sender, _duplicataId, _quantidade, _validade, block.chainid, address(this)));

        // Aplicação do prefixo padrão da Ethereum ("\\x19Ethereum Signed Message:\\n32")
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(mensagemHash);

        // Validação criptográfica: confirma se a assinatura pertence ao kycSigner autorizado
        if (ECDSA.recover(ethSignedMessageHash, _assinatura) != kycSigner) revert KYCInvalido();

        Duplicata storage dup = duplicatas[_duplicataId];

        if (dup.statusDuplicata != StatusDuplicata.Disponivel) revert CaptacaoNaoDisponivel();
        if (block.timestamp > dup.dataVencimento) revert PrazoExpirado();
        if (_quantidade == 0 || _quantidade > dup.fracoesDisponiveis) revert QuantidadeIndisponivel();

        uint256 custoTotal = _quantidade * dup.precoVendaFracao;

        // Effects (Ajuste de estado interno)
        dup.fracoesDisponiveis -= _quantidade;

        emit FracoesAdquiridas(_duplicataId, msg.sender, _quantidade);

        // Encerramento automático da captação se esgotar o estoque
        if (dup.fracoesDisponiveis == 0) {
            dup.statusDuplicata = StatusDuplicata.Captado;
            saldosCedentes[dup.cedente] += (dup.totalFracoes * dup.precoVendaFracao);
            emit CaptacaoEncerrada(_duplicataId, dup.valorNominalTotal);
        }

        // Cunhagem do token ERC-1155 correspondente
        _mint(msg.sender, _duplicataId, _quantidade, "");

        // Transferência segura de Stablecoin ERC-20 do Investidor para o Contrato
        TOKEN_LIQUIDADOR.safeTransferFrom(msg.sender, address(this), custoTotal);
    }

    /**
     * @notice Liquida a duplicata via Oráculo após quitação pelo Sacado (RF05)
     */
    function liquidarTitulo(uint256 _duplicataId) external nonReentrant onlyRole(ORACULO_ROLE) whenNotPaused {
        Duplicata storage dup = duplicatas[_duplicataId];

        if (dup.statusDuplicata != StatusDuplicata.Captado) revert TituloNaoCaptado();

        dup.statusDuplicata = StatusDuplicata.Liquidado;

        emit TituloLiquidado(_duplicataId);

        // Transferência segura do valor nominal em Stablecoins do Oráculo para o Contrato
        TOKEN_LIQUIDADOR.safeTransferFrom(msg.sender, address(this), dup.valorNominalTotal);
    }

    /**
     * @notice Permite o saque das frações pelo investidor aplicando CEI e Mutex (RF06, RF07; RNF01, RNF02)
     */
    function resgatarFracoesInvestidor(uint256 _duplicataId) external nonReentrant whenNotPaused {
        Duplicata storage dup = duplicatas[_duplicataId];

        // Checks
        if (dup.statusDuplicata != StatusDuplicata.Liquidado) revert TituloNaoLiquidado();
        uint256 fracoesDetidas = balanceOf(msg.sender, _duplicataId);
        if (fracoesDetidas == 0) revert SemFracoesParaResgate();

        // Cálculo atômico da valor devido
        uint256 valorDevido = (fracoesDetidas * dup.valorNominalTotal) / dup.totalFracoes;

        // Effects (Queima os tokens do investidor ANTES da transferência)
        _burn(msg.sender, _duplicataId, fracoesDetidas);
        emit FracoesResgatadas(_duplicataId, msg.sender, valorDevido);

        // Interactions (Transferência segura de Stablecoin ERC-20 para o investidor)
        TOKEN_LIQUIDADOR.safeTransfer(msg.sender, valorDevido);
    }

    /**
     * @notice Permite ao Cedente resgatar os recursos captados em Stablecoins
     */
    function resgatarSaldoCedente() external nonReentrant whenNotPaused {
        uint256 saldo = saldosCedentes[msg.sender];
        if (saldo == 0) revert SemSaldoDisponivel();

        saldosCedentes[msg.sender] = 0;
        emit SaldoResgatado(msg.sender, saldo);

        // Transferência segura de Stablecoin ERC-20 para a PME Cedente
        TOKEN_LIQUIDADOR.safeTransfer(msg.sender, saldo);
    }

    /**
     * @notice Sobrescrita exigida pelo ERC1155 e AccessControl
     */
    function supportsInterface(bytes4 interfaceId) public view override(ERC1155, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}
