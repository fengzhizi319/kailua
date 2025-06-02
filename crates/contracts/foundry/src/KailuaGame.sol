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

import "./vendor/FlatOPImportV1.4.0.sol";
import "./vendor/FlatR0ImportV2.0.2.sol";
import "./KailuaLib.sol";
import "./KailuaTournament.sol";
import "./KailuaTreasury.sol";

contract KailuaGame is KailuaTournament {
    /// @notice Semantic version.
    /// @custom:semver 0.1.0
    string public constant version = "0.1.0";

    // ------------------------------
    // Immutable configuration
    // ------------------------------

    /// @notice The duration after which the proposal is accepted
    Duration public immutable MAX_CLOCK_DURATION;

    /// @notice The timestamp of the genesis l2 block
    uint256 public immutable GENESIS_TIME_STAMP;

    /// @notice The time between l2 blocks
    uint256 public immutable L2_BLOCK_TIME;

    /// @notice The minimum gap between the l1 and proposed l2 tip timestamps
    uint256 public immutable PROPOSAL_TIME_GAP;

    constructor(
        KailuaTreasury _kailuaTreasury,
        uint256 _genesisTimeStamp,
        uint256 _l2BlockTime,
        uint256 _proposalTimeGap,
        Duration _maxClockDuration
    )
        KailuaTournament(
            IKailuaTreasury(address(_kailuaTreasury)),
            _kailuaTreasury.RISC_ZERO_VERIFIER(),
            _kailuaTreasury.FPVM_IMAGE_ID(),
            _kailuaTreasury.ROLLUP_CONFIG_HASH(),
            _kailuaTreasury.PROPOSAL_OUTPUT_COUNT(),
            _kailuaTreasury.OUTPUT_BLOCK_SPAN(),
            _kailuaTreasury.GAME_TYPE(),
            _kailuaTreasury.OPTIMISM_PORTAL()
        )
    {
        GENESIS_TIME_STAMP = _genesisTimeStamp;
        L2_BLOCK_TIME = _l2BlockTime;
        PROPOSAL_TIME_GAP = _proposalTimeGap;
        MAX_CLOCK_DURATION = _maxClockDuration;
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
        // Expected length: 0x72
        // - 0x04 selector                      0x00 0x04
        // - 0x14 creator address               0x04 0x18
        // - 0x20 root claim                    0x18 0x38
        // - 0x20 l1 head                       0x38 0x58
        // - 0x18 extraData:                    0x58 0x70
        //      + 0x08 l2BlockNumber            0x58 0x60
        //      + 0x08 parentGameIndex          0x60 0x68
        //      + 0x08 duplicationCounter       0x68 0x70
        // - 0x02 CWIA bytes                    0x70 0x72
        if (msg.data.length != 0x72) {
            revert BadExtraData();
        }

        // Only allow monotonic duplication counter
        uint256 duplicationCounter_ = duplicationCounter();
        if (duplicationCounter_ > 0) {
            bytes memory extra = abi.encodePacked(msg.data[0x58:0x68], uint64(duplicationCounter_ - 1));
            (IDisputeGame previousDuplicate,) = DISPUTE_GAME_FACTORY.games(GAME_TYPE, rootClaim(), extra);
            if (address(previousDuplicate) == address(0x0)) {
                revert InvalidDuplicationCounter();
            }
        }

        // Do not initialize a game that does not cover the required number of l2 blocks
        if (l2BlockNumber() != parentGame().l2BlockNumber() + PROPOSAL_OUTPUT_COUNT * OUTPUT_BLOCK_SPAN) {
            revert BlockNumberMismatch(parentGame().l2BlockNumber(), l2BlockNumber());
        }

        // Store the intermediate output blob hashes
        for (uint256 i = 0; i < PROPOSAL_BLOBS; i++) {
            bytes32 hash = blobhash(i);
            if (hash == 0x0) {
                revert BlobHashMissing(i, PROPOSAL_BLOBS);
            }
            proposalBlobHashes.push(Hash.wrap(hash));
        }

        // Verify that parent game is known by the treasury
        KailuaTournament parentGame_ = parentGame();
        if (KAILUA_TREASURY.proposerOf(address(parentGame_)) == address(0x0)) {
            revert InvalidParent();
        }

        // If a proof was submitted, do not allow bad proposals to be created
        if (!parentGame_.isViableSignature(signature())) {
            revert ProvenFaulty();
        }

        // Prohibit null claims
        if (rootClaim().raw() == 0x0) {
            revert UnexpectedRootClaim(rootClaim());
        }

        // Register this new game in the parent game's contract
        parentGame_.appendChild();

        // Do not permit proposals if l2 block is still inside the proposal gap
        if (block.timestamp < minCreationTime().raw()) {
            revert ProposalGapRemaining(block.timestamp, minCreationTime().raw());
        }
    }

    // ------------------------------
    // IDisputeGame implementation
    // ------------------------------

    /// @inheritdoc IDisputeGame
    function extraData() external pure returns (bytes memory extraData_) {
        // The extra data starts at the second word within the cwia calldata and
        // is 24 bytes long.
        extraData_ = _getArgBytes(0x54, 0x18);
    }

    /// @inheritdoc IDisputeGame
    function resolve() external returns (GameStatus status_) {
        // INVARIANT: Resolution cannot occur unless the game is currently in progress.
        if (status != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        // INVARIANT: Optimistic resolution cannot occur unless parent game is resolved.
        KailuaTournament parentGame_ = parentGame();
        if (parentGame_.status() != GameStatus.DEFENDER_WINS) {
            revert OutOfOrderResolution();
        }

        // INVARIANT: Cannot resolve unless proven valid or the clock has expired
        if (parentGame_.validChildSignature() != 0) {
            if (signature() != parentGame_.validChildSignature()) {
                revert ProvenFaulty();
            }
        } else if (getChallengerDuration(block.timestamp).raw() > 0) {
            revert ClockNotExpired();
        }

        // INVARIANT: Can only resolve the last remaining child
        if (parentGame_.pruneChildren(parentGame_.childCount() * 2) != this) {
            revert NotProven();
        }

        // Mark resolution timestamp
        resolvedAt = Timestamp.wrap(uint64(block.timestamp));

        // Update the status and emit the resolved event, note that we're performing a storage update here.
        emit Resolved(status = status_ = GameStatus.DEFENDER_WINS);
    }

    // ------------------------------
    // Immutable instance data
    // ------------------------------

    /// @notice The index of the parent game in the `DisputeGameFactory`.
    function parentGameIndex() public pure returns (uint64 parentGameIndex_) {
        parentGameIndex_ = _getArgUint64(0x5C);
    }

    /// @notice The number of duplicate proposals preceeding this one.
    function duplicationCounter() public pure returns (uint64 duplicationCounter_) {
        duplicationCounter_ = _getArgUint64(0x64);
    }

    /// @inheritdoc KailuaTournament
    function parentGame() public view override returns (KailuaTournament parentGame_) {
        (,, IDisputeGame parentDisputeGame) = DISPUTE_GAME_FACTORY.gameAtIndex(parentGameIndex());

        // Interpret parent game as another instance of this game type
        parentGame_ = KailuaTournament(address(parentDisputeGame));
    }

    // ------------------------------
    // Fault proving
    // ------------------------------

    /// @inheritdoc KailuaTournament
    function verifyIntermediateOutput(
        uint64 outputNumber,      // 要验证的输出序号（对应特定L2区块）
        uint256 outputFe,         // 声明的字段元素值（需验证的数值）
        bytes calldata blobCommitment, // KZG多项式承诺（对应数据块）
        bytes calldata kzgProof       // KZG证明（用于验证字段元素）
    ) external override returns (bool success) {
        // 步骤1：计算目标数据块索引（将输出序号映射到特定blob）
        uint256 blobIndex = KailuaKZGLib.blobIndex(outputNumber);

        // 步骤2：计算字段元素在blob中的位置（4096个字段元素/blob）
        uint32 blobPosition = KailuaKZGLib.fieldElementIndex(outputNumber);

        // 步骤3：生成版本化KZG哈希（包含版本字节的承诺哈希）
        bytes32 proposalBlobHash = KailuaKZGLib.versionedKZGHash(blobCommitment);
        // Note: Only known blobs can be used to validate an intermediate output
        if (proposalBlobHash != proposalBlobHashes[blobIndex].raw()) {
            success = false;
        } else {
	// 步骤4：执行KZG证明验证（核心数学验证）
            success = KailuaKZGLib.verifyKZGBlobProof(
                proposalBlobHash,    // 已存储的承诺哈希
                blobPosition,        // 字段元素位置
                outputFe,            // 需验证的数值
                blobCommitment,      // 多项式承诺
                kzgProof             // 评估证明
            );
        }

    /// @inheritdoc KailuaTournament
    function getChallengerDuration(uint256 asOfTimestamp) public view override returns (Duration duration_) {
        // INVARIANT: The game must be in progress to query the remaining time to respond to a given claim.
        if (status != GameStatus.IN_PROGRESS) {
            revert GameNotInProgress();
        }

        // Compute the duration elapsed of the potential challenger's clock.
        uint64 elapsed = uint64(asOfTimestamp - createdAt.raw());
        uint64 maximum = MAX_CLOCK_DURATION.raw();
        duration_ = elapsed >= maximum ? Duration.wrap(0) : Duration.wrap(maximum - elapsed);
    }

    /// @inheritdoc KailuaTournament
    function minCreationTime() public view override returns (Timestamp minCreationTime_) {
        minCreationTime_ =
            Timestamp.wrap(uint64(GENESIS_TIME_STAMP + l2BlockNumber() * L2_BLOCK_TIME + PROPOSAL_TIME_GAP));
    }
}
