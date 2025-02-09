//
//  RelayType.swift
//  Tor
//
//  Created by Ruven on 14.11.20.
//

import Foundation

enum RelayCommand: UInt8 {
    // tor-spec.txt 3. "Cell Packet format"
    // tor-spec.txt 6.1. "Relay cells"

    case BEGIN = 1
    case DATA = 2
    case END = 3
    case CONNECTED = 4
    case SENDME = 5
    case EXTEND = 6
    case EXTENDED = 7
    case TRUNCATE = 8
    case TRUNCATED = 9
    case DROP = 10
    case RESOLVE = 11
    case RESOLVED = 12
    case BEGIN_DIR = 13
    case EXTEND2 = 14
    case EXTENDED2 = 15
}
