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
pragma solidity ^0.8.24;

import "./KailuaLib.sol";
import "./vendor/FlatOPImportV1.4.0.sol";
import "./vendor/FlatOPImportV1.4.0.sol";
import "./vendor/FlatR0ImportV2.0.2.sol";

abstract contract KailuaTournament is Clone, IDisputeGame {
    // ------------------------------
    // Immutable configuration
    // ------------------------------

    /// @notice The Kailua Treasury Implementation contract address
    IKailuaTreasury public immutable KAILUA_TREASURY;

    /// @notice The RISC Zero verifier contract
    IRiscZeroVerifier public immutable RISC_ZERO_VERIFIER;

    /// @notice The RISC Zero image id of the fault proof program
    bytes32 public immutable FPVM_IMAGE_ID;

    /// @notice The hash of the game configuration
    bytes32 public immutable ROLLUP_CONFIG_HASH;

    /// @notice The number of outputs a proposal must publish
    uint256 public immutable PROPOSAL_OUTPUT_COUNT;

    /// @notice The number of blocks each output must cover
    uint256 public immutable OUTPUT_BLOCK_SPAN;

    /// @notice The number of blobs a claim must provide
    uint256 public immutable PROPOSAL_BLOBS;

    /// @notice The game type ID
    GameType public immutable GAME_TYPE;

    /// @notice The OptimismPortal2 instance
    OptimismPortal2 public immutable OPTIMISM_PORTAL;

    /// @notice The DisputeGameFactory instance
    DisputeGameFactory public immutable DISPUTE_GAME_FACTORY;

    constructor(
        IKailuaTreasury _kailuaTreasury,
        IRiscZeroVerifier _verifierContract,
        bytes32 _imageId,
        bytes32 _configHash,
        uint256 _proposalOutputCount,
        uint256 _outputBlockSpan,
        GameType _gameType,
        OptimismPortal2 _optimismPortal
    ) {
        KAILUA_TREASURY = _kailuaTreasury;
        RISC_ZERO_VERIFIER = _verifierContract;
        FPVM_IMAGE_ID = _imageId;
        ROLLUP_CONFIG_HASH = _configHash;
        PROPOSAL_OUTPUT_COUNT = _proposalOutputCount;
        OUTPUT_BLOCK_SPAN = _outputBlockSpan;
        // discard published root commitment in calldata
        _proposalOutputCount--;
        PROPOSAL_BLOBS = (_proposalOutputCount / KailuaKZGLib.FIELD_ELEMENTS_PER_BLOB)
            + ((_proposalOutputCount % KailuaKZGLib.FIELD_ELEMENTS_PER_BLOB) == 0 ? 0 : 1);
        GAME_TYPE = _gameType;
        OPTIMISM_PORTAL = _optimismPortal;
        DISPUTE_GAME_FACTORY = OPTIMISM_PORTAL.disputeGameFactory();
    }

    function initializeInternal() internal {
        // INVARIANT: The game must not have already been initialized.
        if (createdAt.raw() > 0) revert AlreadyInitialized();

        // Allow only the treasury to create new games
        if (gameCreator() != address(KAILUA_TREASURY)) {
            revert Blacklisted(gameCreator(), address(KAILUA_TREASURY));
        }

        // Set the game's starting timestamp
        createdAt = Timestamp.wrap(uint64(block.timestamp));

        // Set the game's index in the factory
        gameIndex = DISPUTE_GAME_FACTORY.gameCount();

        // Read respected status
        wasRespectedGameTypeWhenCreated = OPTIMISM_PORTAL.respectedGameType().raw() == GAME_TYPE.raw();
    }

    // ------------------------------
    // Game State
    // ------------------------------

    /// @notice The blob hashes used to create the game
    Hash[] public proposalBlobHashes;

    /// @notice The game's index in the factory
    uint256 public gameIndex;

    /// @notice The address of the prover of a proposal signature
    mapping(bytes32 => address) public prover;

    /// @notice The timestamp of when the first proof for a proposal signature was made
    mapping(bytes32 => Timestamp) public provenAt;

    /// @notice The current proof status of a proposal signature
    mapping(bytes32 => ProofStatus) public proofStatus;

    /// @notice The proposals extending this proposal
    KailuaTournament[] public children;

    /// @notice The first surviving contender
    uint64 public contenderIndex;

    /// @notice Duplicates of the last surviving contender proposal
    uint64[] public contenderDuplicates;

    /// @notice The next unprocessed opponent
    uint64 public opponentIndex;

    /// @notice The signature of the child accepted through a validity proof
    bytes32 public validChildSignature;

    /// @notice Returns the hash of the output claim and all blob hashes associated with this proposal
    function signature() public view returns (bytes32 signature_) {
        // note: the absence of the l1Head in the signature implies that
        // the proposal gap should absolutely guarantee derivation
        signature_ = sha256(abi.encodePacked(rootClaim().raw(), proposalBlobHashes));
    }

    /// @notice Returns whether a child can be considered valid
    function isViableSignature(bytes32 childSignature) public view returns (bool isViableSignature_) {
        if (validChildSignature != 0) {
            isViableSignature_ = childSignature == validChildSignature;
        } else {
            isViableSignature_ = proofStatus[childSignature] != ProofStatus.FAULT;
        }
    }

    /// @notice Returns the address of the prover of the specified signature or the prover of the valid signature
    function getPayoutRecipient(bytes32 childSignature) internal view returns (address payoutRecipient) {
        payoutRecipient = prover[childSignature];
        if (payoutRecipient == address(0x0)) {
            payoutRecipient = prover[validChildSignature];
        }
    }

    /// @notice Returns true iff the child proposal was eliminated
    function isChildEliminated(KailuaTournament child) internal view returns (bool) {
        address _proposer = KAILUA_TREASURY.proposerOf(address(child));
        uint256 eliminationRound = KAILUA_TREASURY.eliminationRound(_proposer);
        if (eliminationRound == 0 || eliminationRound > child.gameIndex()) {
            // This proposer has not been eliminated as of their proposal at gameIndex
            return false;
        }
        return true;
    }

    /// @notice Returns the number of children
    function childCount() external view returns (uint256 count_) {
        count_ = children.length;
    }

    /// @notice Registers a new proposal that extends this one
    function appendChild() external {
        // INVARIANT: The calling contract is a newly deployed contract by the dispute game factory
        if (!KAILUA_TREASURY.isProposing()) {
            revert UnknownGame();
        }

        // INVARIANT: The calling KailuaGame contract is not referring to itself as a parent
        if (msg.sender == address(this)) {
            revert InvalidParent();
        }

        // INVARIANT: No longer accept proposals after resolution
        if (contenderIndex < children.length && children[contenderIndex].status() == GameStatus.DEFENDER_WINS) {
            revert ClaimAlreadyResolved();
        }

        // Append new child to children list
        children.push(KailuaTournament(msg.sender));
    }

    /// @notice Returns the amount of time left for challenges as of the input timestamp.
    function getChallengerDuration(uint256 asOfTimestamp) public view virtual returns (Duration duration_);

    /// @notice Returns the earliest time at which this proposal could have been created
    function minCreationTime() public view virtual returns (Timestamp minCreationTime_);

    /// @notice Returns the parent game contract.
    function parentGame() public view virtual returns (KailuaTournament parentGame_);

    /// @notice Returns the proposer address
    function proposer() public view returns (address proposer_) {
        proposer_ = KAILUA_TREASURY.proposerOf(address(this));
    }

    /// @notice Verifies that an intermediate output was part of the proposal
    function verifyIntermediateOutput(
        uint64 outputNumber,
        uint256 outputFe,
        bytes calldata blobCommitment,
        bytes calldata kzgProof
    ) external virtual returns (bool success);

    function updateProofStatus(
        address payoutRecipient,  // 证明者的奖励接收地址
        bytes32 childSignature,   // 子提案的签名标识
        ProofStatus outcome       // 证明结果状态（VALIDITY/FAULT）
    ) internal {
        // 更新子提案的证明状态
        // Update proof status
        proofStatus[childSignature] = outcome;

        // Announce proof status
        // 触发Proven事件通知状态变更
        emit Proven(childSignature, outcome);

        // 记录证明者的地址
        // Set the game's prover address
        prover[childSignature] = payoutRecipient;

        // 记录证明时间戳（使用当前区块时间）
        // Set the game's proving timestamp
        provenAt[childSignature] = Timestamp.wrap(uint64(block.timestamp));
    }

    // ------------------------------
    // IDisputeGame implementation
    // ------------------------------

    /// @inheritdoc IDisputeGame
    Timestamp public createdAt;

    /// @inheritdoc IDisputeGame
    Timestamp public resolvedAt;

    /// @inheritdoc IDisputeGame
    GameStatus public status;

    /// @inheritdoc IDisputeGame
    function gameType() external view returns (GameType gameType_) {
        gameType_ = GAME_TYPE;
    }

    /// @inheritdoc IDisputeGame
    function gameCreator() public pure returns (address creator_) {
        creator_ = _getArgAddress(0x00);
    }

    /// @inheritdoc IDisputeGame
    function rootClaim() public pure returns (Claim rootClaim_) {
        rootClaim_ = Claim.wrap(_getArgBytes32(0x14));
    }

    /// @inheritdoc IDisputeGame
    function l1Head() public pure returns (Hash l1Head_) {
        l1Head_ = Hash.wrap(_getArgBytes32(0x34));
    }

    /// @notice The l2BlockNumber of the claim's output root.
    function l2BlockNumber() public pure returns (uint256 l2BlockNumber_) {
        l2BlockNumber_ = uint256(_getArgUint64(0x54));
    }

    /// @inheritdoc IDisputeGame
    function gameData() external view returns (GameType gameType_, Claim rootClaim_, bytes memory extraData_) {
        gameType_ = GAME_TYPE;
        rootClaim_ = this.rootClaim();
        extraData_ = this.extraData();
    }

    /// @notice True iff the Kailua GameType was respected by OptimismPortal at time of creation
    bool public wasRespectedGameTypeWhenCreated;

    // ------------------------------
    // Tournament
    // ------------------------------

    /// @notice Eliminates children until at least one remains
    function pruneChildren(uint256 stepLimit) external returns (KailuaTournament) {
        // INVARIANT: Only finalized proposals may prune tournaments
        if (status != GameStatus.DEFENDER_WINS) {
            revert GameNotResolved();
        }

        // INVARIANT: No tournament to play without at least one child
        if (children.length == 0) {
            revert NotProposed();
        }

        // Resume from prior surviving contender
        uint64 u = contenderIndex;
        // Resume from prior unprocessed opponent
        uint64 v = opponentIndex;
        // Abort if out of bounds
        if (u == children.length) {
            return KailuaTournament(address(0x0));
        }
        // Advance v if needed
        if (v <= u) {
            // INVARIANT: contenderDuplicates is empty
            v = u + 1;
        }

        // Note: u < children.length
        // Fetch contender details
        KailuaTournament contender = children[u];
        bytes32 contenderSignature = contender.signature();

        // Ensure survivor decision finality after resolution
        if (contender.status() == GameStatus.DEFENDER_WINS) {
            return contender;
        }

        // If the contender is invalid then we eliminate it and find the next viable contender using the opponent
        // pointer. This search could terminate early if the elimination limit is reached.
        // If the contender is valid and its proposer is not eliminated, this is skipped.
        if (!isViableSignature(contenderSignature) || isChildEliminated(contender)) {
            // INVARIANT: If branch entered through isChildEliminated condition, contenderDuplicates is empty

            // Eliminate duplicates
            address payoutRecipient = getPayoutRecipient(contenderSignature);
            for (uint256 i = contenderDuplicates.length; i > 0 && stepLimit > 0; (i--, stepLimit--)) {
                KailuaTournament duplicate = children[contenderDuplicates[i - 1]];
                if (!isChildEliminated(duplicate)) {
                    KAILUA_TREASURY.eliminate(address(duplicate), payoutRecipient);
                }
                contenderDuplicates.pop();
            }

            // Abort if elimination allowance exhausted before eliminating all duplicate contenders
            if (stepLimit == 0) {
                return KailuaTournament(address(0x0));
            }

            // Eliminate contender
            if (!isChildEliminated(contender)) {
                KAILUA_TREASURY.eliminate(address(contender), payoutRecipient);
            }
            stepLimit--;

            // Find next viable contender
            // INVARIANT: v > max(u, contenderDuplicates);
            u = v;
            for (; u < children.length && stepLimit > 0; (u++, stepLimit--)) {
                // Skip if previously eliminated
                contender = children[u];
                if (isChildEliminated(contender)) {
                    continue;
                }
                // Eliminate if faulty
                contenderSignature = contender.signature();
                if (!isViableSignature(contenderSignature)) {
                    // eliminate the unviable contender
                    KAILUA_TREASURY.eliminate(address(contender), getPayoutRecipient(contenderSignature));
                    continue;
                }
                // Select u as next viable contender
                break;
            }
            // Store contender
            contenderIndex = u;
            // Select the next possible opponent
            v = u + 1;
        }

        // Eliminate faulty opponents if we've landed on a viable contender
        if (u < children.length && isViableSignature(children[u].signature())) {
            // Iterate over opponents to eliminate them
            for (; v < children.length && stepLimit > 0; (v++, stepLimit--)) {
                KailuaTournament opponent = children[v];
                // If the contender hasn't been challenged for as long as the timeout, declare them winner
                if (contender.getChallengerDuration(opponent.createdAt().raw()).raw() == 0) {
                    // Note: This implies eliminationLimit > 0
                    break;
                }
                // If the opponent proposer is eliminated, skip
                if (isChildEliminated(opponent)) {
                    continue;
                }
                // Append contender duplicate
                bytes32 opponentSignature = opponent.signature();
                if (opponentSignature == contenderSignature) {
                    contenderDuplicates.push(v);
                    continue;
                }
                // If there is insufficient proof data, abort
                // Validity: The contender is the proven child, the opponent must be incorrect
                // Fault: The contender is not proven faulty, the opponent may (not) be.
                if (isViableSignature(opponentSignature)) {
                    revert NotProven();
                }
                // eliminate the opponent with the unviable proposal
                KAILUA_TREASURY.eliminate(address(opponent), getPayoutRecipient(opponentSignature));
            }

            // INVARIANT: v > u && contender == children[u]
            // Record incremental opponent elimination progress
            opponentIndex = v;

            // Return the sole survivor if no more matches can be played
            if (v == children.length || stepLimit > 0) {
                return contender;
            }
        }

        // No survivor yet
        return KailuaTournament(address(0x0));
    }

    // ------------------------------
    // Validity proving
    // ------------------------------

    /// @notice Returns the hash of all blob hashes associated with this proposal
    function blobsHash() public view returns (bytes32 blobsHash_) {
        blobsHash_ = sha256(abi.encodePacked(proposalBlobHashes));
    }

    /// @notice Proves that a proposal is valid
    function proveValidity(address payoutRecipient, uint64 childIndex, bytes calldata encodedSeal) external {
        KailuaTournament childContract = children[childIndex];
        // INVARIANT: Can only prove validity of unresolved proposals
        if (childContract.status() != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        // Store validity proof data (deleted on revert)
        validChildSignature = childContract.signature();

        // INVARIANT: Proofs can only be submitted once
        if (provenAt[validChildSignature].raw() != 0) {
            revert AlreadyProven();
        }

        // INVARIANT: No longer accept proofs after resolution
        if (contenderIndex < children.length && children[contenderIndex].status() == GameStatus.DEFENDER_WINS) {
            revert ClaimAlreadyResolved();
        }

        // Calculate the expected precondition hash if blob data is necessary for proposal
        bytes32 preconditionHash = bytes32(0x0);
        if (PROPOSAL_OUTPUT_COUNT > 1) {
            preconditionHash = sha256(
                abi.encodePacked(
                    uint64(l2BlockNumber()),
                    uint64(PROPOSAL_OUTPUT_COUNT),
                    uint64(OUTPUT_BLOCK_SPAN),
                    childContract.blobsHash()
                )
            );
        }

        // Calculate the expected block number
        uint64 claimBlockNumber = uint64(l2BlockNumber() + PROPOSAL_OUTPUT_COUNT * OUTPUT_BLOCK_SPAN);

        // Construct the expected journal
        bytes32 journalDigest = sha256(
            abi.encodePacked(
                // The address of the recipient of the payout for this proof
                payoutRecipient,
                // The blob equivalence precondition hash
                preconditionHash,
                // The L1 head hash containing the safe L2 chain data that may reproduce the L2 head hash.
                childContract.l1Head().raw(),
                // The accepted output
                rootClaim().raw(),
                // The proposed output
                childContract.rootClaim().raw(),
                // The claim block number
                claimBlockNumber,
                // The rollup configuration hash
                ROLLUP_CONFIG_HASH,
                // The FPVM Image ID
                FPVM_IMAGE_ID
            )
        );

        // Revert on proof verification failure
        RISC_ZERO_VERIFIER.verify(encodedSeal, FPVM_IMAGE_ID, journalDigest);

        // Mark the child as proven valid
        updateProofStatus(payoutRecipient, validChildSignature, ProofStatus.VALIDITY);
    }

    // ------------------------------
    // Fault proving
    // ------------------------------

    /// @notice Proves that a proposal committed to an incorrect transition
    // proveOutputFault 处理主输出错误（核心业务逻辑）
    function proveOutputFault(
        address payoutRecipient,    // 奖励接收地址（通常为证明者或惩罚接收方）
        uint64[2] calldata co,      // 争议坐标数组 [子提案索引, 争议输出索引]
        bytes calldata encodedSeal,  // RISC Zero的零知识证明密封数据
        bytes32 acceptedOutputHash, // 父提案接受的输出哈希（正确值）
        uint256 proposedOutputFe,   // 子提案声明的输出字段元素（需验证的错误值）
        bytes32 computedOutputHash, // 实际计算得到的正确输出哈希
        bytes[] calldata blobCommitments,  // KZG多项式承诺数组（用于验证中间输出）
        bytes[] calldata kzgProofs        // KZG证明数组（对应承诺的证明）
    ) external {
        // 获取子合约实例（根据坐标数组第一个元素索引）
        KailuaTournament childContract = children[co[0]];
        // INVARIANT: Proofs cannot be submitted unless the child is playing.
        // 验证1：父合约必须处于进行中状态，即还没有确认哪个子合约是正确的。
        // 防止对已解决/结束的提案进行证明
        if (childContract.status() != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        bytes32 childSignature = childContract.signature();
        // INVARIANT: Proofs can only be submitted once
        // 验证2：防止重复提交证明
        // 确保当前签名尚未被证明过
        if (proofStatus[childSignature] != ProofStatus.NONE) {
            revert AlreadyProven();
        }

        // INVARIANT: No longer accept proofs after resolution
        if (contenderIndex < children.length && children[contenderIndex].status() == GameStatus.DEFENDER_WINS) {
            revert ClaimAlreadyResolved();
        }

        // INVARIANT: Proofs can only pertain to computed outputs
        // 验证4：争议索引有效性检查
        // 确保争议输出索引不超过提案输出总数
        if (co[1] >= PROPOSAL_OUTPUT_COUNT) {
            revert InvalidDisputedClaimIndex();
        }

        // Validate the common output root.
        // 验证5：验证共同输出根（父级接受的值）
        if (co[1] == 0) {
            // Note: acceptedOutputHash cannot be a reduced fe because the comparison below will fail
            // The safe output is the parent game's output when proving the first output
            // 当争议索引为0时，直接对比父合约的根声明，因为第0个输出就是父合约的根声明
            // 确保接受的输出哈希与当前合约的根声明一致
            require(acceptedOutputHash == rootClaim().raw(), "bad acceptedOutput");
        } else {
            // Note: acceptedOutputHash cannot be a reduced fe because the journal would not be provable
            // Prove common output publication
            // 对于非首个输出，验证前序输出的正确性
            // 使用KZG证明验证子合约的中间输出
            require(
                childContract.verifyIntermediateOutput(
                    co[1] - 1, // 前一个输出索引
                    KailuaKZGLib.hashToFe(acceptedOutputHash), // 转换为字段元素
                    blobCommitments[0],   // 首个blob承诺
                    kzgProofs[0]          // 对应的KZG证明
                ),
                "bad acceptedOutput kzg"
            );
        }

        // Validate the claimed output root.
        // 验证6：验证提案声明的输出根
        if (co[1] == PROPOSAL_OUTPUT_COUNT - 1) {
            // INVARIANT: Proofs can only show disparities
            // 当争议为最后一个输出时，直接对比子合约的根声明
            if (computedOutputHash == childContract.rootClaim().raw()) {
                revert NoConflict();
            }
        } else {
            // Note: proposedOutputFe must be a canonical point or point eval precompile call will fail
            // Prove divergent output publication
            // 对于中间输出，使用KZG证明验证其正确性
            require(
                childContract.verifyIntermediateOutput(
                    co[1], // 当前争议索引
                    proposedOutputFe,
                    blobCommitments[blobCommitments.length - 1], // 最后一个blob承诺
                    kzgProofs[kzgProofs.length - 1]              // 最后一个KZG证明
                ),
                "bad proposedOutput kzg"
            );
            // INVARIANT: Proofs can only show disparities
            if (KailuaKZGLib.hashToFe(computedOutputHash) == proposedOutputFe) {
                revert NoConflict();
            }
        }

        // Construct the expected journal
        // 构造零知识证明所需的日志摘要
        {
            // 计算声明的区块号：当前L2区块号 + (输出索引+1)*区块跨度
            uint64 claimedBlockNumber = uint64(l2BlockNumber() + (co[1] + 1) * OUTPUT_BLOCK_SPAN);
            bytes32 journalDigest = sha256(
                abi.encodePacked(
                // The address of the recipient of the payout for this proof
                    payoutRecipient,
                    // No precondition hash
                    bytes32(0x0),
                    // The L1 head hash containing the safe L2 chain data that may reproduce the L2 head hash.
                    childContract.l1Head().raw(),
                    // The latest finalized L2 output root.
                    acceptedOutputHash,
                    // The L2 output root claim.
                    computedOutputHash,
                    // The L2 claim block number.
                    claimedBlockNumber,
                    // The rollup configuration hash
                    ROLLUP_CONFIG_HASH,
                    // The FPVM Image ID
                    FPVM_IMAGE_ID
                )
            );

            // reverts on failure
            // 执行零知识证明验证（核心安全操作）
            // 验证密封数据、镜像ID和日志摘要的一致性
            RISC_ZERO_VERIFIER.verify(encodedSeal, FPVM_IMAGE_ID, journalDigest);
        }

        updateProofStatus(payoutRecipient, childSignature, ProofStatus.FAULT);
    }

    /// @notice Proves that a proposal contains invalid intermediate data
    function proveNullFault(
        // 支付奖励接收地址，奖励证明者
        address payoutRecipient,
        // [子提案索引, 尾部数据索引]
        // 子提案索引：要挑战的子合约在children数组中的位置
        // 尾部数据索引：必须 ≥ PROPOSAL_OUTPUT_COUNT，表示主输出之后的非法数据位置
        uint64[2] calldata co,
        // 错误的尾部字段元素（必须是非零的无效数据）
        uint256 proposedOutputFe,
        // 单个blob的KZG多项式承诺（用于验证非法数据的存在）
        bytes calldata blobCommitment,
        // 对应承诺的KZG证明（通过预编译合约验证）
        bytes calldata kzgProof
    ) external {
        // 获取要挑战的子合约实例
        KailuaTournament childContract = children[co[0]];
        // INVARIANT: Proofs cannot be submitted unless the children are playing.
        // 验证1：子合约必须处于进行中状态
        if (childContract.status() != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        // 获取子合约唯一签名标识（由rootClaim和blob哈希生成）
        bytes32 childSignature = childContract.signature();
        // INVARIANT: Proofs can only be submitted once
        // 验证2：防止重复提交证明
        if (proofStatus[childSignature] != ProofStatus.NONE) {
            revert AlreadyProven();
        }

        // INVARIANT: No longer accept proofs after resolution
        if (contenderIndex < children.length && children[contenderIndex].status() == GameStatus.DEFENDER_WINS) {
            revert ClaimAlreadyResolved();
        }

        // INVARIANT: Proofs can only pertain to intermediate commitments
        // 验证3：必须针对尾部数据（索引必须超出主输出范围）
        if (co[1] == PROPOSAL_OUTPUT_COUNT - 1) {
            revert InvalidDisputedClaimIndex();
        }

        // We expect all trail data to be zeroed, while non-trail data to be non-zero
        bool isTrailFe = co[1] >= PROPOSAL_OUTPUT_COUNT;
        bool isZeroFe = proposedOutputFe == 0;
        if (isTrailFe == isZeroFe) {
            revert NoConflict();
        }

        // Because the root claim is considered the last published output, we shift the output offset down by one to
        // correctly point to the target trailing zero output
        // INVARIANT: The divergence occurs at a proper blob index
        uint64 feOffset = isTrailFe ? co[1] - 1 : co[1];
        // 验证4：非法数据必须出现在最后一个blob中
        // PROPOSAL_BLOBS-1 表示最后一个blob的索引
        if (KailuaKZGLib.blobIndex(feOffset) >= PROPOSAL_BLOBS) {
            revert InvalidDataRemainder();// 防止在非尾部blob添加非法数据
        }

        // Validate the claimed output root publications
        // Note: proposedOutputFe must be a canonical field element or point eval precompile call will fail
        // 核心验证：通过预编译合约验证KZG证明
        // 验证proposedOutputFe确实存在于承诺的blob中
        require(
            childContract.verifyIntermediateOutput(feOffset, proposedOutputFe, blobCommitment, kzgProof),
            "bad proposedOutput kzg"
        );

        // Update dispute status based on trailing data
        // 更新子合约状态为FAULT（触发惩罚机制）
        updateProofStatus(payoutRecipient, childSignature, ProofStatus.FAULT);
    }
}
