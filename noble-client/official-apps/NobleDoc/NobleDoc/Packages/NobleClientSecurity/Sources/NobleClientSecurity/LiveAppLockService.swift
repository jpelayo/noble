// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import LocalAuthentication

/// Live implementation of ``AppLockService`` using LocalAuthentication
/// (Touch ID on Mac, Face ID / Touch ID on iOS).
public struct LiveAppLockService: AppLockService, Sendable {
    public init() {}

    public var isBiometricAvailable: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    public func authenticateWithBiometrics(reason: String) async throws -> Bool {
        let context = LAContext()
        context.localizedFallbackTitle = "Use Password"

        // Falls back to device passcode if biometrics unavailable
        let policy: LAPolicy = .deviceOwnerAuthentication

        do {
            let success = try await context.evaluatePolicy(policy, localizedReason: reason)
            return success
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel:
                return false
            case .userFallback:
                // User chose password fallback — still counts as cancel from biometric perspective
                return false
            default:
                throw error
            }
        }
    }
}
