//
//  RelayCell.swift
//  Tor
//
//  Created by Ruven on 14.11.20.
//

import Foundation

protocol RelayCell {
    var command: RelayCommand { get }
    var streamId: UInt16 { get }
    
    func serialize(node: OnionRouter) -> Data?
}

extension RelayCell {
    
    func buildCell(with payload: Data, for node: OnionRouter) -> Data? {
        var relayCell = Data()
        relayCell.packInt(command.rawValue)
        relayCell.packInt(UInt16(0))
        relayCell.packInt(streamId)
        relayCell.packInt(UInt32(0))
        relayCell.packInt(UInt16(payload.count))
        relayCell += payload + Data(count: 498 - payload.count)
        guard let calcDigest = node.crypto?.getDigest(data: relayCell) else {
            print("RelayCellExtend2: Failed to calculate digest")
            return nil
        }
        relayCell.replaceSubrange(5..<9, with: calcDigest.subdata(in: 0..<4))
        return relayCell
    }
    
}

struct RelayCellExtend2: RelayCell {
    
    private(set) var command: RelayCommand = .EXTEND2
    private(set) var streamId: UInt16
    
    private let targetRouter: OnionRouter
    private let keyAgreement: KeyAgreement
    
    init(streamId: UInt16, targetRouter: OnionRouter, keyAgreement: KeyAgreement) {
        self.targetRouter = targetRouter
        self.keyAgreement = keyAgreement
        self.streamId = streamId
    }
    
    func buildPayload() -> Data? {
        var payload = Data()
        payload.packInt(UInt8(2)) // Number link specifiers
        payload.packInt(UInt8(0)) // Link specifier type (TSL IPv4)
        payload.packInt(UInt8(6)) // Link specifier length (IPv4 + OR Port)
        guard let ipData = Data(ip: targetRouter.ip) else {
            print("Circuit: failed to unwrap extend relay ip address")
            return nil
        }
        payload += ipData
        payload.packInt(targetRouter.torPort)
        payload.packInt(UInt8(2)) // Legacy identity
        payload.packInt(UInt8(20)) // Link specifier length
        payload += Data(hex: targetRouter.identity)
        payload.packInt(UInt16(2))
        payload.packInt(UInt16(keyAgreement.getHandshake().count))
        payload += keyAgreement.getHandshake()
        print("RelayCellExtend2: payload \(payload.toHexString())")
        
        return payload
    }
    
    func serialize(node: OnionRouter) -> Data? {
        guard let payload = buildPayload() else {
            return nil
        }
        return buildCell(with: payload, for: node)
    }

}

struct RelayCellExtended2: RelayCell {
    
    private(set) var command: RelayCommand = .EXTENDED2
    private(set) var streamId: UInt16
    
    let serverKey: Data
    let auth: Data
    
    init(streamId: UInt16, frame: Data) {
        self.streamId = streamId
        var data = frame
        let length = data.unpackInt(type: UInt16.self)
        serverKey = data.extract(in: 0..<32)
        auth = data.extract(in: 0..<Data.Index(length-32))
    }
    
    func serialize(node: OnionRouter) -> Data? {
        print("RelayCellExtended2: Serialization not implemented")
        return Data()
    }
    
}

struct RelayCellBegin: RelayCell {
    
    private(set) var command: RelayCommand = .BEGIN
    private(set) var streamId: UInt16
    
    let host: String
    let port: UInt16
    
    init(streamId: UInt16, host: String, port: UInt16) {
        self.host = host
        self.port = port
        self.streamId = streamId
    }
    
    func serialize(node: OnionRouter) -> Data? {
        var payload = Data("\(host):\(String(port))".utf8) + Data(count: 1)
        payload += Data(count: 4) // FLAGS: does not support IPv6, does support IPv4, IPv6 not preferred
    
        return buildCell(with: payload, for: node)
    }
}

struct RelayCellEnd: RelayCell {
    
    private(set) var command: RelayCommand = .END
    private(set) var streamId: UInt16
    
    let reason: RelayEndReason
    
    init?(streamId: UInt16, frame: Data) {
        self.streamId = streamId
        var data = frame
        guard let rer = RelayEndReason(rawValue: data.unpackInt(type: UInt8.self)) else {
            return nil
        }
        self.reason = rer
    }
    
    func serialize(node: OnionRouter) -> Data? {
        print("RelayCellEnd: Serialize not implemented yet")
        return nil
    }
}

struct RelayCellTruncated: RelayCell {
    
    private(set) var command: RelayCommand = .TRUNCATED
    private(set) var streamId: UInt16
    
    let reason: DestroyReason
    
    init?(streamId: UInt16, frame: Data) {
        self.streamId = streamId
        var data = frame
        guard let rer = DestroyReason(rawValue: data.unpackInt(type: UInt8.self)) else {
            return nil
        }
        self.reason = rer
    }
    
    func serialize(node: OnionRouter) -> Data? {
        print("RelayCellEnd: Serialize not implemented yet")
        return nil
    }
}

struct RelayCellConnected: RelayCell {
    
    private(set) var command: RelayCommand = .CONNECTED
    private(set) var streamId: UInt16
    
    let address: String
    let ttl: UInt32
    
    init(streamId: UInt16, frame: Data) {
        self.streamId = streamId
        var data = frame
        let header = data.extract(in: 0..<4)
        if header.bytes.allSatisfy({ $0 == UInt8(0) }){
            // Type IPv6 Payload
            _ = data.unpackInt(type: UInt8.self)
            address = data.extract(in: 0..<16).toIpString()!
        } else {
            // Type IPv4 Payload
            address = header.toIpString()!
        }
        ttl = data.unpackInt(type: UInt32.self)
    }
    
    func serialize(node: OnionRouter) -> Data? {
        print("RelayCellEnd: Serialize not implemented. Should not be implemented due to backward designation")
        return nil
    }
}

struct RelayCellData: RelayCell {
    
    private(set) var command: RelayCommand = .DATA
    private(set) var streamId: UInt16
    
    let data: Data
    
    init(streamId: UInt16, frame: Data) {
        self.streamId = streamId
        data = frame
    }
    
    func serialize(node: OnionRouter) -> Data? {
        return buildCell(with: data, for: node)
    }
}

struct RelayCellSendme: RelayCell {
    
    private(set) var command: RelayCommand = .SENDME
    
    let streamId: UInt16
    let version: UInt8
    let digest: Data
    
    init(streamId: UInt16, frame: Data) {
        self.streamId = streamId
        var data = frame
        version = data.unpackInt(type: UInt8.self)
        if version != 0 {
            print("RelayCellSendme: Unsupported version \(version)")
        }
        // TODO: Implement parsing of version 1 cells
        digest = Data(count: 0)
    }
    
    init(streamId: UInt16, version: UInt8 = 0, digest: Data = Data(count: 0)) {
        self.streamId = streamId
        self.version = version
        self.digest = digest
    }
    
    func serialize(node: OnionRouter) -> Data? {
        if version == 1 {
            var payload = Data()
            payload.packInt(version)
            payload.packInt(UInt16(digest.count))
            print("RelayCellSendMe: Serializing digest with count: \(digest.count)")
            payload += digest
            return buildCell(with: payload, for: node)
        } else {
            // Version 0 cell as default
            return buildCell(with: Data(count: 1), for: node)
        }
    }
}
