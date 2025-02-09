//
//  Circuit.swift
//  Tor
//
//  Created by Ruven on 11.11.20.
//

import Foundation

enum CircuitStatus {
    case inactive
    case creating(guardRelay: OnionRouter, keyAgreement: KeyAgreement, completion: () -> Void)
    case created
    case extending(router: OnionRouter, keyAgreement: KeyAgreement, completion: () -> Void)
    case extended
    case closed
}

class Circuit {
    var circuitId: UInt32
    
    private weak var socket: TorSocket?
    var status: CircuitStatus = .inactive
    
    private var nodes: [OnionRouter] = []
    private var windows: [TorWindow] = []
    private var relayCellHandlers: [UInt16: (RelayCell) -> Void] = [:]
    
    private let window = TorWindow(size: 1000, increment: 100)
    
    init(socket: TorSocket) {
        circuitId = UInt32.random(in: 2147483648...4294967295)
        self.socket = socket
        setupCellHandler()
        setupRelayCellHandler()
    }
    
    deinit {
        print("Circuit \(self.circuitId): Deinitializing circuit")
    }
    
    private func setupCellHandler() {
        self.socket?.registerCellHandler(with: circuitId, handler: { [weak self] cell in
            switch cell.command {
            case .CREATED2:
                if case .creating(let guardRelay, let keyAgreement, let completion) = self?.status {
                    self?.created(cell: cell as! CellCreated2, guardRelay: guardRelay, keyAgreement: keyAgreement, completion: completion)
                } else {
                    print("Circuit \(self!.circuitId): Received CREATED2 cell but in status \(String(describing: self?.status))")
                }
            case .RELAY:
                let cellRelay = cell as! CellRelay
                guard let decryptedData = self?.decrypt(data: cellRelay.encryptedData) else {
                    print("Circuit \(self!.circuitId): Failed to decrypt relay data")
                    return
                }
                guard let relayCell = cellRelay.parse(decryptedData: decryptedData) else {
                    print("Circuit \(self!.circuitId): Failed to parse relay cell contents")
                    return
                }
                
                if case .DATA = relayCell.command {
                    if let sendMeRequired = self?.window.receivedData(),
                       sendMeRequired {
                        print("Circuit \(self!.circuitId): Sending SendMe. Window (deliver = \(self!.window.deliverWindow), package = \(self!.window.packageWindow))")
                        self?.window.deliveredSendMe()
                        let recognizedDigest = (self?.nodes.last?.crypto?.getBackwardDigest())!
                        print("Circuit: \(self!.circuitId): Recognized digest for SendMe deliver#\(self!.window.deliverWindow): \(recognizedDigest.toHexString())")
                        self?.sendCircuitLevelSendMe(digest: (self?.nodes.last?.crypto?.getBackwardDigest())!)
                    }
                    
                    print("Circuit \(self!.circuitId): Received RELAY_DATA with rolling digest: \((self?.nodes.last?.crypto?.getBackwardDigest())!.toHexString()) Window (deliver = \(self!.window.deliverWindow)")
                }
                self?.notify(streamId: relayCell.streamId, cell: relayCell)
            default:
                break
            }
        })
    }
    
    private func setupRelayCellHandler() {
        registerRelayCellHandler(with: 0) { [unowned self] cell in
            switch cell.command {
            case .EXTENDED2:
                if case .extending(let router, let keyAgreement, let completion) = status {
                    extended(cell: cell as! RelayCellExtended2, router: router, keyAgreement: keyAgreement, completion: completion)
                } else {
                    print("Circuit \(self.circuitId): Received EXTENDED2 cell but in status \(status)")
                }
            case .DATA:
                print("Circuit \(self.circuitId): Received circuit level RELAY_DATA package (streamID = 0)")
            case .SENDME:
                print("Circuit \(self.circuitId): Received Relay SENDME cell")
                window.receivedSendMe()
            case .END:
                let endCell = cell as! RelayCellEnd
                status = .closed
                socket?.removeCellHandler(with: circuitId)
                print("Circuit \(self.circuitId): Received Relay END cell with reason: \(String(describing: endCell.reason))")
            case .TRUNCATED:
                let truncCell = cell as! RelayCellTruncated
                status = .closed
                socket?.removeCellHandler(with: circuitId)
                print("Circuit \(self.circuitId): Received Relay TRUNCATED cell with reason: \(String(describing: truncCell.reason))")
            default:
                print("Circuit \(self.circuitId): Received unexpected cell: \(cell.command)")
                break
            }
        }
    }
    
    func create(guardRelay: OnionRouter, completion: @escaping () -> Void) {
        print("Circuit \(self.circuitId): Creating new circuit")
        guard let keyAgreement = KeyAgreementNTOR(router: guardRelay) else {
            print("Circuit \(self.circuitId): Failed to initialize KeyAgreementNTOR")
            return
        }
        socket?.sendCell(cell: CellCreate2(circuitId: circuitId, handshakeType: UInt16(2), handshakeData: keyAgreement.getHandshake())) {
            self.status = .creating(guardRelay: guardRelay, keyAgreement: keyAgreement, completion: completion)
        }
    }
    
    private func created(cell: CellCreated2, guardRelay: OnionRouter, keyAgreement: KeyAgreement, completion: @escaping () -> Void) {
        keyAgreement.completeHandshake(serverKey: cell.serverKey, auth: cell.auth)
        nodes.append(guardRelay)
        windows.append(TorWindow(size: 1000, increment: 100))
        status = .created
        completion()
    }
    
    
    func extend(router: OnionRouter, completion: @escaping () -> Void) {
        guard let keyAgreement = KeyAgreementNTOR(router: router) else {
            print("Circuit \(self.circuitId): Failed to initialize KeyAgreementNTOR")
            return
        }
        
        guard let encryptedData = encrypt(cell: RelayCellExtend2(streamId: 0, targetRouter: router, keyAgreement: keyAgreement)) else {
            print("Circuit \(self.circuitId): Failed to build EXTEND2 cell")
            return
        }
        
        socket?.sendCell(cell: CellRelayEarly(circuitId: circuitId, encryptedData: encryptedData)) {
            print("Circuit \(self.circuitId): Send RELAY_EXTEND2 cell")
            self.status = .extending(router: router, keyAgreement: keyAgreement, completion: completion)
        }
    }
    
    private func extended(cell: RelayCellExtended2, router: OnionRouter, keyAgreement: KeyAgreement, completion: @escaping () -> Void) {
        keyAgreement.completeHandshake(serverKey: cell.serverKey, auth: cell.auth)
        nodes.append(router)
        windows.append(TorWindow(size: 1000, increment: 100))
        status = .extended
        print("Circuit \(self.circuitId): Extended successfully. Node #\(self.nodes.count) added")
        completion()
    }
    
    func sendRelayCell(cell: RelayCell) {
        if window.authorizeSend() {
            guard let encryptedData = encrypt(cell: cell) else {
                print("Circuit \(self.circuitId): Failed to build Relay cell of type \(cell.command) for stream \(cell.streamId)")
                return
            }
            
            socket?.sendCell(cell: CellRelay(circuitId: circuitId, frame: encryptedData)) { }
        } else {
            print("Circuit \(self.circuitId): Authorization to send Relay Cell denied due to no available package window.")
        }
    }
    
    func sendSendMe(streamId: UInt16, completion: @escaping () -> Void) {
        let cell = RelayCellSendme(streamId: streamId)
        guard let encryptedData = encrypt(cell: cell) else {
            print("Circuit \(self.circuitId): Failed to build BEGIN cell")
            return
        }
        
        socket?.sendCell(cell: CellRelay(circuitId: circuitId, frame: encryptedData)) {
            print("Circuit \(self.circuitId): Send RELAY_SENDME relay cell for Stream \(streamId)")
            completion()
        }
    }
    
    func sendCircuitLevelSendMe(digest: Data) {
        let cell = RelayCellSendme(streamId: 0, version: 1, digest: digest)
        guard let encryptedData = encryptForNode(cell: cell, nodeNumber: 2) else {
            print("Circuit \(self.circuitId): Failed to build \(cell.command) relay cell")
            return
        }
        
        socket?.sendCell(cell: CellRelay(circuitId: circuitId, frame: encryptedData)) { [weak self] in
            print("Circuit \(self!.circuitId): Send circuit level RELAY_SENDME relay cell (digest = \(digest.toHexString()))for node \(2): \(self!.nodes[2].name)")
        }
    }
    
    func registerRelayCellHandler(with streamId: UInt16, handler: @escaping (RelayCell) -> Void) {
        relayCellHandlers[streamId] = handler
    }
    
    func removeRelayCellHandler(with streamId: UInt16) {
        relayCellHandlers.removeValue(forKey: streamId)
    }
    
    private func notify(streamId: UInt16, cell: RelayCell) {
        guard let handler = relayCellHandlers[streamId] else {
            print("Circuit \(self.circuitId): No handler registered for streamId: \(streamId)")
            return
        }
        handler(cell)
    }
    
    private func encryptForNode(cell: RelayCell, nodeNumber: Int) -> Data? {
        guard nodeNumber < nodes.count,
              var data = cell.serialize(node: nodes[nodeNumber]) else {
            print("Circuit \(self.circuitId): Failed to build \(cell.command) relay cell")
            return nil
        }
        
        for nodeId in (0..<nodeNumber).reversed() {
            guard let encryptedData = nodes[nodeId].crypto?.encrypt(relayPayload: data) else {
                return nil
            }
            data = encryptedData
        }
        return data
    }
    
    private func encrypt(cell: RelayCell) -> Data? {
        guard let node = nodes.last,
              var data = cell.serialize(node: node) else {
            print("Circuit \(self.circuitId): Failed to build \(cell.command) relay cell")
            return nil
        }
        
        for node in nodes.reversed() {
            guard let encryptedData = node.crypto?.encrypt(relayPayload: data) else {
                return nil
            }
            data = encryptedData
        }
        return data
    }
    
    private func decrypt(data: Data) -> Data? {
        var decryptedData = data
        for node in nodes {
            guard let decrypt = node.crypto?.decrypt(relayPayload: decryptedData) else {
                print("Circuit \(self.circuitId): Decryption failed")
                return nil
            }
            decryptedData = decrypt
            if isDecrypted(frame: decryptedData, node: node) {
                return decryptedData
            }
        }
        print("Circuit \(self.circuitId): Decryption not recognized after stripping all onion skin layers")
        return nil
    }
    
    private func isDecrypted(frame: Data, node: OnionRouter) -> Bool {
        var data = frame
        _ = data.unpackInt(type: UInt8.self)
        let recognized = data.unpackInt(type: UInt16.self)
        if recognized != 0 {
            return false
        } else {
            guard let crypto = node.crypto else {
                return false
            }
            return crypto.checkDigest(data: frame)
        }
    }
}
