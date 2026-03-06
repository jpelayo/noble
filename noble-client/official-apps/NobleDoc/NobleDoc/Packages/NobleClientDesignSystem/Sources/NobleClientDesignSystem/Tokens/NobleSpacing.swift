// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Spacing scale tokens for the NOBLE design system.
///
/// Based on a 4px base unit, matching the dashboard CSS `--gap-*` custom properties.
public enum NobleSpacing {
    /// 4pt — Extra-small gap.
    public static let xs: CGFloat = 4

    /// 8pt — Small gap.
    public static let sm: CGFloat = 8

    /// 16pt — Default gap.
    public static let md: CGFloat = 16

    /// 24pt — Large gap.
    public static let lg: CGFloat = 24

    /// 32pt — Extra-large gap.
    public static let xl: CGFloat = 32
}
