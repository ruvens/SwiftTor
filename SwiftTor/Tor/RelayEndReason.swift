//
//  RelayEndReason.swift
//  Tor
//
//  Created by Ruven on 16.11.20.
//

import Foundation

enum RelayEndReason: UInt8 {
    case MISC = 1
    case RESOLVEFAILED = 2
    case CONNECTREFUSED = 3
    case EXITPOLICY = 4
    case DESTROY = 5
    case DONE = 6
    case TIMEOUT = 7
    case NOROUTE = 8
    case HIBERNATING = 9
    case INTERNAL = 10
    case RESOURCELIMIT = 11
    case CONNRESET = 12
    case TORPROTOCOL = 13
    case NOTDIRECTORY = 14
}
