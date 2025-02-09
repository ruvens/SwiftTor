//
//  DestroyReason.swift
//  Tor
//
//  Created by on 01.11.22.
//

import Foundation

enum DestroyReason: UInt8 {
    // tor-spec.txt 5.4. "Tearing down circuits"
    
    case NONE = 0
    case PROTOCOL = 1
    case INTERNAL = 2
    case REQUESTED = 3
    case HIBERNATING = 4
    case RESOURCELIMIT = 5
    case CONNECTFAILED = 6
    case OR_IDENTITY = 7
    case CHANNEL_CLOSED = 8
    case FINISHED = 9
    case TIMEOUT = 10
    case DESTROYED = 11
    case NOSUCHSERVICE = 12
}
