//
//  Item.swift
//  ChatterboxiOS
//
//  Created by Adrian on 12/7/26.
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
