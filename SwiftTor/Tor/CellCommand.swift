//
//  CellCommand.swift
//  Tor
//
//  Created by Ruven on 10.11.20.
//

import Foundation

enum CellCommand: UInt8 {
    // tor-spec.txt 3. "Cell Packet format"
    // tor-spec.txt 6.1. "Relay cells"

    // Fixed-length command values.
    case PADDING = 0
    case CREATE = 1
    case CREATED = 2
    case RELAY = 3
    case DESTROY = 4
    case CREATE_FAST = 5
    case CREATED_FAST = 6
    case NETINFO = 8
    case RELAY_EARLY = 9
    case CREATE2 = 10
    case CREATED2 = 11

    // Variable-length command values.
    case VERSIONS = 7
    case VPADDING = 128
    case CERTS = 129
    case AUTH_CHALLENGE = 130
    case AUTHENTICATE = 131
}
