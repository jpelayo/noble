import Testing
@testable import NobleClientCore

@Suite("NobleAmount Tests")
struct NobleAmountTests {

    @Test func zeroAmount() {
        let amount = NobleAmount.zero
        #expect(amount.atomic == 0)
    }
}
