//
//  TorWindow.swift
//  Tor
//
//  Created by Ruven on 29.11.20.
//

import Foundation

class TorWindow {
    
    private let size: Int
    private let increment: Int
    
    var packageWindow: Int
    var deliverWindow: Int
    
    init(size: Int = 1000, increment: Int = 100) {
        self.size = size
        self.increment = increment
        packageWindow = size
        deliverWindow = size
    }
    
    func receivedSendMe() {
        packageWindow += increment
    }
    
    func deliveredSendMe() {
        deliverWindow += increment
    }
    
    func receivedData() -> Bool {
        deliverWindow -= 1
        if deliverWindow <= (size - increment) {
            return true
        } else {
            return false
        }
    }
    
    func authorizeSend() -> Bool {
        packageWindow -= 1
        if packageWindow < 0 {
            return false
        } else {
            return true
        }
    }
}
