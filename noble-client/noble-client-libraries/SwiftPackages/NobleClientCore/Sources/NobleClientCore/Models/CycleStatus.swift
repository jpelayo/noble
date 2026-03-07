// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Current consensus cycle status from the node.
public struct CycleStatus: Codable, Equatable, Sendable {
    /// The current cycle number.
    public let cycleNumber: UInt64
    /// The current phase name ("Proposal", "Voting", "Reflection", "Propagation").
    public let phase: String
    /// Seconds remaining in the current phase.
    public let phaseRemainingSecs: UInt64
    /// Seconds remaining in the current cycle.
    public let cycleRemainingSecs: UInt64

    public init(
        cycleNumber: UInt64 = 0,
        phase: String = "Proposal",
        phaseRemainingSecs: UInt64 = 0,
        cycleRemainingSecs: UInt64 = 0
    ) {
        self.cycleNumber = cycleNumber
        self.phase = phase
        self.phaseRemainingSecs = phaseRemainingSecs
        self.cycleRemainingSecs = cycleRemainingSecs
    }
}
