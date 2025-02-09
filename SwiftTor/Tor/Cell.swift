//
//  Cell.swift
//  Tor
//
//  Created by Ruven on 10.11.20.
//

import Foundation

protocol Cell {

    var circuitId: UInt32 { get }
    var command: CellCommand { get }
    
    func serialize(protocolVersion: Int) -> Data
    
}

extension Cell {
    var maxPayLoadSize: Int { return 509 }
    
    func getCellHeader(protocolVersion: Int) -> Data {
        var data = Data()
        if protocolVersion < 4 {
            data.packInt(UInt16(circuitId))
        } else {
            data.packInt(circuitId)
        }
        data.packInt(command.rawValue)
        return data
    }
}

struct CellVersions: Cell {
    
    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .VERSIONS
    
    let versions: [Int]
    
    init(circuitId: UInt32, versions: [Int]) {
        self.circuitId = circuitId
        self.versions = versions
    }
    
    init(circuitId: UInt32, frame: Data) {
        self.circuitId = circuitId
        
        var data = frame
        var versions: [Int] = []
        for _ in 0..<(frame.count/2) {
            versions.append(Int(data.unpackInt(type: UInt16.self)))
        }
        
        self.versions = versions
    }
    
    func serialize(protocolVersion: Int) -> Data {
        // tor-spec.txt 3. "Cell Packet format"
        
        var data = Data()
        data.packInt(UInt16(circuitId))
        data.packInt(command.rawValue)
        data.packInt(UInt16(2*versions.count))
        for version in versions {
            data.packInt(UInt16(version))
        }
        
        return data
    }
}

struct CellCerts: Cell {
    
    enum CertType: UInt8 {
        case linkKeyCertificate = 1
        case identityCertificate = 2
        case authenticateCellLinkCertificate = 3
        case ed25519SigningKey = 4
        case tlsLinkCertificate = 5
        case ed25519AuthentivateCellKey = 6
        case ed25519Identity = 7
    }

    struct Certificate {
        let type: CertType
        let cert: Data
    }
    
    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .CERTS
    
    private var certs: [Certificate] = []

    init(circuitId: UInt32, frame: Data) {
        self.circuitId = circuitId
        
        var data = frame
        let numCerts = data.unpackInt(type: UInt8.self)
        for _ in 0..<numCerts {
            let certType = data.unpackInt(type: UInt8.self)
            let certLength = data.unpackInt(type: UInt16.self)
            let cert = data.extract(in: 0..<Data.Index(certLength))
            if let parsedCertType = CertType(rawValue: certType) {
                certs.append(Certificate(type: parsedCertType, cert: cert))
            }
        }
    }
    
    func serialize(protocolVersion: Int) -> Data {
        print("CellCert: Serialization not implemented")
        return Data()
    }
}


struct CellAuthChallenge: Cell {
    
    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .AUTH_CHALLENGE
    
    private var challenge: Data
    private var methods: [UInt16] = []
    
    init(circuitId: UInt32, frame: Data) {
        self.circuitId = circuitId
        
        var data = frame
        challenge = data.extract(in: 0..<32)
        let numMethods = data.unpackInt(type: UInt16.self)
        for _ in 0..<numMethods {
            methods.append(data.unpackInt(type: UInt16.self))
        }
    }
    
    func serialize(protocolVersion: Int) -> Data {
        print("CellAuthChallenge: Serialization not implemented")
        return Data()
    }
}

struct CellNetInfo: Cell {
    
    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .NETINFO
    
    let timestamp: UInt32
    let otherAddress: Data
    let ourAddresses: [Data]
    
    init?(circuitId: UInt32, otherAddress: String, ourAddresses: [String]) {
        self.circuitId = circuitId
        timestamp = UInt32(modf(NSDate().timeIntervalSince1970).0)
        guard let otherIp = Data(ip: otherAddress) else { return  nil }
        self.otherAddress = otherIp
        self.ourAddresses = ourAddresses.map({ Data(ip: $0) }).filter({ $0 != nil }).map({ $0! })
    }
    
    init(circuitId: UInt32, frame: Data) {
        self.circuitId = circuitId
        
        var data = frame
        timestamp = data.unpackInt(type: UInt32.self)
        _ = data.unpackInt(type: UInt8.self) // address type
        let addressLength = data.unpackInt(type: UInt8.self)
        otherAddress = data.extract(in: 0..<Data.Index(addressLength))
        
        let numOurAddr = data.unpackInt(type: UInt8.self)
        var ourAddr: [Data] = []
        for _ in 0..<numOurAddr {
            _ = data.unpackInt(type:UInt8.self) // address type
            let addressLength = data.unpackInt(type: UInt8.self)
            ourAddr.append(data.extract(in: 0..<Data.Index(addressLength)))
        }
        ourAddresses = ourAddr
    }
    
    func serialize(protocolVersion: Int) -> Data {
        // tor-spec.txt 3. "Cell Packet format"
        // tor-spec.txt 4.5 "NETINFO cells"
                
        var data = Data()
        if protocolVersion < 4 {
            data.packInt(UInt16(circuitId))
        } else {
            data.packInt(circuitId)
        }
        data.packInt(command.rawValue)
        data.packInt(timestamp)
        data.packInt(UInt8(otherAddress.count == 4 ? 4 : 6))
        data.packInt(UInt8(otherAddress.count))
        data += otherAddress
        data.packInt(UInt8(ourAddresses.count))
        for adr in ourAddresses {
            data.packInt(UInt8(adr.count == 4 ? 4 : 6))
            data.packInt(UInt8(adr.count))
            data += adr
        }
        
        return data + Data(count: 514 - data.count)
    }
}

struct CellCreate2: Cell {

    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .CREATE2
    
    let handshakeType: UInt16
    let handshakeData: Data
    
    init(circuitId: UInt32, handshakeType: UInt16, handshakeData: Data) {
        self.circuitId = circuitId
        self.handshakeType = handshakeType
        self.handshakeData = handshakeData
    }
    
    func serialize(protocolVersion: Int) -> Data {
        // tor-spec.txt 3. "Cell Packet format"
        // tor-spec.txt 5.1 "CREATE and CREATED cells"
        
        var data = Data()
        if protocolVersion < 4 {
            data.packInt(UInt16(circuitId))
        } else {
            data.packInt(circuitId)
        }
        data.packInt(command.rawValue)
        data.packInt(handshakeType)
        data.packInt(UInt16(handshakeData.count))
        data += handshakeData
        
        return data + Data(count: 514 - data.count)
    }
}

struct CellCreated2: Cell {

    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .CREATED2
    
    let serverKey: Data
    let auth: Data
    
    init(circuitId: UInt32, frame: Data) {
        self.circuitId = circuitId
        
        var data = frame
        _ = data.unpackInt(type: UInt16.self)
        serverKey = data.extract(in: 0..<32)
        auth = data.extract(in: 0..<32)
    }
    
    func serialize(protocolVersion: Int) -> Data {
        print("CellCreated2: Serialization not implemented")
        return Data()
    }
}

struct CellDestroy: Cell {
    
    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .DESTROY
    
    let reason: DestroyReason
    
    init?(circuitId: UInt32, frame: Data) {
        self.circuitId = circuitId
        
        var data = frame
        guard let dr = DestroyReason(rawValue: data.unpackInt(type: UInt8.self)) else {
            return nil
        }
        self.reason = dr
    }
    
    func serialize(protocolVersion: Int) -> Data {
        print("CellDestroy: Serialization not implemented")
        return Data()
    }
}

struct CellRelayEarly: Cell {
    
    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .RELAY_EARLY
    
    let encryptedData: Data
    
    init(circuitId: UInt32, encryptedData: Data) {
        self.circuitId = circuitId
        self.encryptedData = encryptedData
    }
    
    func serialize(protocolVersion: Int) -> Data {
        var data = Data()
        if protocolVersion < 4 {
            data.packInt(UInt16(circuitId))
        } else {
            data.packInt(circuitId)
        }
        data.packInt(command.rawValue)
        data += encryptedData
        return data + Data(count: 514 - data.count)
    }
}

struct CellRelay: Cell {
    
    private(set) var circuitId: UInt32
    private(set) var command: CellCommand = .RELAY
    
    var encryptedData: Data
        
    init(circuitId: UInt32, frame: Data) {
        self.circuitId = circuitId
        self.encryptedData = frame
    }
    
    func parse(decryptedData: Data) -> RelayCell? {
        var frame = decryptedData
        guard let relayCommand = RelayCommand(rawValue: frame.unpackInt(type: UInt8.self)) else {
            print("CellRelay: Failed to parse relay command")
            return nil
        }
        
        _ = frame.unpackInt(type: UInt16.self) //recognized
        let streamId = frame.unpackInt(type: UInt16.self)
        _ = frame.extract(in: 0..<4) //digest
        let dataLength = frame.unpackInt(type: UInt16.self)
        guard dataLength <= 498 else {
            print("CellRelay: Parsing error. Data Length too long")
            return nil
        }
        let data = frame.extract(in: 0..<Data.Index(dataLength))
        
        switch relayCommand {
        case .EXTENDED2:
            return RelayCellExtended2(streamId: streamId, frame: data)
        case .CONNECTED:
            return RelayCellConnected(streamId: streamId, frame: data)
        case .DATA:
            return RelayCellData(streamId: streamId, frame: data)
        case .END:
            return RelayCellEnd(streamId: streamId, frame: data)
        case .TRUNCATED:
            return RelayCellTruncated(streamId: streamId, frame: data)
        default:
            return nil
        }
    }
    
    func serialize(protocolVersion: Int) -> Data {
        var data = Data()
        if protocolVersion < 4 {
            data.packInt(UInt16(circuitId))
        } else {
            data.packInt(circuitId)
        }
        data.packInt(command.rawValue)
        data += encryptedData
        
        return data + Data(count: 514 - data.count)
    }
}

