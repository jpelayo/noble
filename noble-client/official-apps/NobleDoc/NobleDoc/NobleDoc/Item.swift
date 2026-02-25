//
//  Item.swift
//  NobleDoc
//
//  Created by pelayo on 25/2/26.
//

import Foundation
import SwiftData

@Model
final class Item {
    var timestamp: Date
    
    init(timestamp: Date) {
        self.timestamp = timestamp
    }
}
