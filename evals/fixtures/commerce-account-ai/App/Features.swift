import Foundation
import StoreKit

struct AIProvider {
    func sendWithConsent(_ text: String) async throws {}
}

func deleteAccount() async throws {}

func checkExternalPurchaseAvailability() async {
    _ = ExternalPurchase.canPresent
}
