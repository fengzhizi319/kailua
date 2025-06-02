// Copyright 2024, 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.15;

import "./vendor/FlatOPImportV1.4.0.sol";
import "./vendor/FlatR0ImportV2.0.2.sol";
import "./KailuaLib.sol";
import "./KailuaTournament.sol";

contract KailuaTreasury is KailuaTournament, IKailuaTreasury {
    /// @notice Semantic version.
    /// @custom:semver 0.1.0
    string public constant version = "0.1.0";

    // ------------------------------
    // Immutable configuration
    // ------------------------------

    /// @notice The initial root claim for the deployment
    Claim public immutable ROOT_CLAIM;// 部署时初始化的根声明（如：0xabcd1234...）

    /// @notice The initial root claim for the deployment
    uint64 public immutable L2_BLOCK_NUMBER;// 初始化L2区块号（如：123456）

    constructor(
        IRiscZeroVerifier _verifierContract,
        bytes32 _imageId,
        bytes32 _configHash,
        uint256 _proposalOutputCount,
        uint256 _outputBlockSpan,
        GameType _gameType,
        OptimismPortal2 _optimismPortal,
        Claim _rootClaim,
        uint64 _l2BlockNumber
    )
        KailuaTournament(
            KailuaTreasury(this),
            _verifierContract,
            _imageId,
            _configHash,
            _proposalOutputCount,
            _outputBlockSpan,
            _gameType,
            _optimismPortal
        )
    {
        ROOT_CLAIM = _rootClaim;
        L2_BLOCK_NUMBER = _l2BlockNumber;
    }

    // ------------------------------
    // IInitializable implementation
    // ------------------------------

    /// @inheritdoc IInitializable
    function initialize() external payable override {
        super.initializeInternal();

        // Revert if the calldata size is not the expected length.
        //
        // This is to prevent adding extra or omitting bytes from to `extraData` that result in a different game UUID
        // in the factory, but are not used by the game, which would allow for multiple dispute games for the same
        // output proposal to be created.
        //
        // Expected length: 0x76
        // - 0x04 selector                      0x00 0x04
        // - 0x14 creator address               0x04 0x18
        // - 0x20 root claim                    0x18 0x38
        // - 0x20 l1 head                       0x38 0x58
        // - 0x1c extraData:                    0x58 0x74
        //      + 0x08 l2BlockNumber            0x58 0x60
        //      + 0x14 kailuaTreasuryAddress    0x60 0x74
        // - 0x02 CWIA bytes                    0x74 0x76
        if (msg.data.length != 0x76) {
            revert BadExtraData();
        }

        // Accept only the initialized root claim
        if (rootClaim().raw() != ROOT_CLAIM.raw()) {
            revert UnexpectedRootClaim(rootClaim());
        }

        // Accept only the initialized l2 block number
        if (l2BlockNumber() != L2_BLOCK_NUMBER) {
            revert BlockNumberMismatch(l2BlockNumber(), L2_BLOCK_NUMBER);
        }

        // Accept only the address of the deployment treasury
        if (treasuryAddress() != address(KAILUA_TREASURY)) {
            revert BadExtraData();
        }
    }

    /// @notice Returns the treasury address used in initialization
    function treasuryAddress() public pure returns (address treasuryAddress_) {
        treasuryAddress_ = _getArgAddress(0x5c);
    }

    // ------------------------------
    // IDisputeGame implementation
    // ------------------------------

    /// @inheritdoc IDisputeGame
    function extraData() external pure returns (bytes memory extraData_) {
        // The extra data starts at the second word within the cwia calldata and
        // is 32 bytes long.
        extraData_ = _getArgBytes(0x54, 0x1c);
    }

    /// @inheritdoc IDisputeGame
    function resolve() external onlyFactoryOwner returns (GameStatus status_) {
        // INVARIANT: Resolution cannot occur unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        // Update the status and emit the resolved event, note that we're performing a storage update here.
        emit Resolved(status = status_ = GameStatus.DEFENDER_WINS);

        // Mark resolution timestamp
        resolvedAt = Timestamp.wrap(uint64(block.timestamp));
    }

    // ------------------------------
    // Fault proving
    // ------------------------------

    /// @inheritdoc KailuaTournament
    function verifyIntermediateOutput(uint64, uint256, bytes calldata, bytes calldata)
        external
        pure
        override
        returns (bool success)
    {
        // No known blobs to reference
    }

    /// @inheritdoc KailuaTournament
    function getChallengerDuration(uint256) public pure override returns (Duration duration_) {
        // No challenge period
    }

    /// @inheritdoc KailuaTournament
    function minCreationTime() public view override returns (Timestamp minCreationTime_) {
        minCreationTime_ = createdAt;
    }

    /// @inheritdoc KailuaTournament
    function parentGame() public view override returns (KailuaTournament parentGame_) {
        parentGame_ = this;
    }

    // ------------------------------
    // IKailuaTreasury implementation
    // ------------------------------

    /// @inheritdoc IKailuaTreasury
    mapping(address => uint256) public eliminationRound;

    /// @inheritdoc IKailuaTreasury
    mapping(address => address) public proposerOf;

    /// @inheritdoc IKailuaTreasury
    function eliminate(address _child, address prover) external {
        //1. 调用者验证
        KailuaTournament child = KailuaTournament(_child);

        // INVARIANT: Only the child's parent may call this
        KailuaTournament parent = child.parentGame();
        // 仅允许父合约调用
        if (msg.sender != address(parent)) {
            revert Blacklisted(msg.sender, address(parent));
        }

        // 2. 提案者存在性验证
        // INVARIANT: Only known proposals may be eliminated
        address eliminated = proposerOf[address(child)];// 通过映射获取原始提议者
        // 拦截未注册提案
        if (eliminated == address(0x0)) {
            revert NotProposed();
        }

        // 3. 防重复淘汰验证
        // INVARIANT: Cannot double-eliminate players
        if (eliminationRound[eliminated] > 0) {
            revert AlreadyEliminated();
        }

        // 4. 记录淘汰状态
        // Record elimination round
        eliminationRound[eliminated] = child.gameIndex();// 记录淘汰轮次

        // 5. 分配奖励
        //eliminations[Bob] = [Alice, Eve]  // Bob淘汰了Alice和Eve的提案
        //eliminations[Dave] = [Charlie]    // Dave淘汰了Charlie
        // Allocate bond to prover
        eliminations[prover].push(eliminated);//分配奖励资格
    }

    /// @inheritdoc IKailuaTreasury
    bool public isProposing;

    // ------------------------------
    // Treasury
    // ------------------------------

    /// @notice The locked collateral required for proposal submission
    uint256 public participationBond;

    /// @notice The locked collateral still paid by proposers for participation
    mapping(address => uint256) public paidBonds;

    /// @notice The list of players each prover has eliminated
    mapping(address => address[]) public eliminations;

    /// @notice The number of eliminations paid out to each prover
    mapping(address => uint256) public eliminationsPaid;

    /// @notice The last proposal made by each proposer
    mapping(address => KailuaTournament) public lastProposal;

    /// @notice The leading proposer that can extend the proposal tree
    address public vanguard;

    /// @notice The duration for which the vanguard may lead
    Duration public vanguardAdvantage;

    /// @notice Boolean flag to prevent re-entrant calls
    bool internal isLocked;

    modifier nonReentrant() {
        require(!isLocked);
        isLocked = true;
        _;
        isLocked = false;
    }

    modifier onlyFactoryOwner() {
        OwnableUpgradeable factoryContract = OwnableUpgradeable(address(DISPUTE_GAME_FACTORY));
        require(msg.sender == factoryContract.owner(), "not owner");
        _;
    }

    /// @notice Pays out the prover for the eliminations it has accrued
    function claimEliminationBonds(uint256 claims) public nonReentrant {
        uint256 claimed = 0;
        uint256 payout = 0;
        for (
            uint256 i = eliminationsPaid[msg.sender];
            claimed < claims && i < eliminations[msg.sender].length;
            (i++, claimed++)
        ) {
            address eliminated = eliminations[msg.sender][i];
            payout += paidBonds[eliminated];
            paidBonds[eliminated] = 0;
        }
        // Increase number of bonds claimed
        if (claimed > 0) {
            eliminationsPaid[msg.sender] += claimed;
        }
        // Transfer payout
        if (payout > 0) {
            pay(payout, msg.sender);
        }
    }

    /// @notice Pays the proposer back its bond
    function claimProposerBond() public nonReentrant {
        // INVARIANT: Can only claim back bond if not eliminated
        if (eliminationRound[msg.sender] != 0) {
            revert AlreadyEliminated();
        }

        // INVARIANT: Can only claim bond back if no pending proposals are left
        KailuaTournament previousGame = lastProposal[msg.sender];
        if (address(previousGame) != address(0x0)) {
            KailuaTournament lastTournament = previousGame.parentGame();
            if (lastTournament.children(lastTournament.contenderIndex()).status() != GameStatus.DEFENDER_WINS) {
                revert GameNotResolved();
            }
        }

        uint256 payout = paidBonds[msg.sender];
        // INVARIANT: Can only claim bond if it is paid
        if (payout == 0) {
            revert NoCreditToClaim();
        }

        // Pay out and clear bond
        paidBonds[msg.sender] = 0;
        pay(payout, msg.sender);
    }

    /// @notice Transfers ETH from the contract's balance to the recipient
    function pay(uint256 amount, address recipient) internal {
        (bool success,) = recipient.call{value: amount}(hex"");
        if (!success) revert BondTransferFailed();
    }

    /// @notice Updates the required bond for new proposals
    function setParticipationBond(uint256 amount) external onlyFactoryOwner {
        participationBond = amount;
        emit BondUpdated(amount);
    }

    /// @notice Updates the vanguard address and advantage duration
    function assignVanguard(address _vanguard, Duration _vanguardAdvantage) external onlyFactoryOwner {
        vanguard = _vanguard;
        vanguardAdvantage = _vanguardAdvantage;
    }

    /// @notice Checks the proposer's bonded amount and creates a new proposal through the factory
    function propose(Claim _rootClaim, bytes calldata _extraData)
        external
        payable
        returns (KailuaTournament tournament)
    {
        // Check proposer honesty
        // [1] 身份验证，检查提议者是否已被淘汰，即是否在黑名单中
        if (eliminationRound[msg.sender] > 0) {
            revert BadAuth();
        }
        // Update proposer bond
        // [2] 保证金处理，更新质押金：将发送的ETH累加到用户的质押账户
        if (msg.value > 0) {
            paidBonds[msg.sender] += msg.value;// 累加保证金
        }
        // Check proposer bond
        // 检查保证金门槛
        if (paidBonds[msg.sender] < participationBond) {
            revert IncorrectBondAmount();
        }
        // Create proposal
        // [3] 创建proposal提案KailuaTournament实例
        isProposing = true;
        tournament = KailuaTournament(address(DISPUTE_GAME_FACTORY.create(GAME_TYPE, _rootClaim, _extraData)));
        isProposing = false;
        // Check proposal progression
        // [4] 提案连续性检查：检查新提案是否能继承上一个提案，检查连续提案的区块号递增性
        KailuaTournament previousGame = lastProposal[msg.sender];
        if (address(previousGame) != address(0x0)) {
            // INVARIANT: Proposers may only extend the proposal set incrementally
            // 确保新提案的L2区块号必须大于上次提案
            if (previousGame.l2BlockNumber() >= tournament.l2BlockNumber()) {
                revert BlockNumberMismatch(previousGame.l2BlockNumber(), tournament.l2BlockNumber());
            }
        }
        // Check whether the proposer must follow a vanguard if one is set
        // [5] Vanguard先锋机制验证，非先锋成员需等待优势期结束
        if (vanguard != address(0x0) && vanguard != msg.sender) {
            // The proposer may only counter the vanguard during the advantage time
            KailuaTournament proposalParent = tournament.parentGame();
            if (proposalParent.childCount() == 1) {
                // Count the advantage clock since proposal was possible
                uint64 elapsedAdvantage = uint64(block.timestamp - tournament.minCreationTime().raw());
                if (elapsedAdvantage < vanguardAdvantage.raw()) {
                    revert VanguardError(address(proposalParent));
                }
            }
        }
        // Record proposer
        // [6] 记录提案关系：记录提案者和提案的映射关系
        proposerOf[address(tournament)] = msg.sender;
        // Record proposal
        lastProposal[msg.sender] = tournament;
    }
}
