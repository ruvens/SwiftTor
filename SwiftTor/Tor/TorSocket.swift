//
//  TorSocket.swift
//  Tor
//
//  Created by Ruven on 10.11.20.
//

import Foundation
import Network

class TorSocket {
    
    enum TorSocketStatus {
        case connecting
        case connected
        case closed
    }
    
    var status: TorSocketStatus = .connecting
    let guardRelay: OnionRouter
    
    private let connection: NWConnection
    
    private var cellHandlers: [UInt32 : (Cell) -> Void] = [:]
    private var connectionListeners: [() -> Void] = []
        
    private let supportedProtocolVersions: Set = [3, 4]
    private var protocolVersion: Int = 3
    
    private var publicIPAdress = ""
    private var buffer = Data(count: 0)
    
    // Basic Socket functionality
    init(guardRelay: OnionRouter) {
        self.guardRelay = guardRelay
        
        let options = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(options.securityProtocolOptions, { (_, trust, completionHandler) in
            //TODO: Fix Apple security overwrite
            completionHandler(true)
        }, .main)
                
        let params = NWParameters(tls: options)
        
        connection = NWConnection(host: NWEndpoint.Host(guardRelay.ip), port: NWEndpoint.Port(rawValue: guardRelay.torPort)!, using: params)
        connection.stateUpdateHandler = stateDidChange(to:)
        connection.start(queue: DispatchQueue(label: "TorSocketQueue"))
        registerCellHandler(with: UInt32(0)) { [unowned self] cell in
            switch cell.command {
            case .VERSIONS:
                let versionsCell = cell as! CellVersions
                self.protocolVersion = self.supportedProtocolVersions.union(versionsCell.versions).max()!
            case .NETINFO:
                let netinfoCell = cell as! CellNetInfo
                self.publicIPAdress = netinfoCell.otherAddress.toIpString()!
                guard let responseNetInfo = CellNetInfo(circuitId: 0, otherAddress: guardRelay.ip, ourAddresses: [self.publicIPAdress]) else {
                    print("TorSocket: Could not build response NETINFO cell")
                    return
                }
                self.sendCell(cell: responseNetInfo) {
                    self.status = .connected
                    self.connectionListeners.forEach { $0() }
                    self.connectionListeners.removeAll()
                }
            default:
                return
            }
        }
        receiveCell()
        sendCell(cell: CellVersions(circuitId: 0, versions: Array(supportedProtocolVersions))) { }
    }
    
    deinit {
        print("TorSocket: Deinitialized")
    }
    
    func connect(completion: @escaping () -> Void) {
        if status == .connected {
            completion()
        } else {
            connectionListeners.append(completion)
        }
    }
    
    private func close() {
        status = .closed
        connection.stateUpdateHandler = nil
        connection.cancel()
    }
    
    private func stateDidChange(to state: NWConnection.State) {
        switch state {
        case .waiting(let error):
            print("TorSocket: Waiting state error \(error.localizedDescription)")
            close()
        case .ready:
            print("TorSocket: Connection Ready")
        case .failed(let error):
            print("TorSocket: Failed state error \(error.localizedDescription)")
            close()
        default:
            break
        }
    }
    
    private func receiveCell() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            (data, _, isComplete, error) in
            if let data = data, !data.isEmpty {
//                print("TorSocket: Data received. Length: \(data.count) Data: \(data.toHexString())")
                self.notifyCellHandlers(frame: data)
                if self.status != .closed {
                    self.receiveCell()
                }
            } else if let error = error {
                print("TorSocket: Error received: \(error.localizedDescription)")
                self.close()
            } else if isComplete {
                print("TorSocket: Completion received")
                self.close()
            }
        }
    }
    
    func sendCell(cell: Cell, completion: @escaping () -> Void) {
        let content = cell.serialize(protocolVersion: protocolVersion)
        connection.send(content: content, completion: .contentProcessed( { error in
            if error != nil {
                print("TorSocket: Send Cell \(cell.command) Failed. Length: \(content.count) Data: \(content as NSData)")
            } else {
                print("TorSocket: Send Cell \(cell.command) Success. Length: \(content.count) Data: \(content as NSData)")
                completion()
            }
        }))
    }
    
    func registerCellHandler(with circuitId: UInt32, handler: @escaping (Cell) -> Void) {
        cellHandlers[circuitId] = handler
    }
    
    func removeCellHandler(with circuitId: UInt32) {
        cellHandlers.removeValue(forKey: circuitId)
    }
    
    private func notifyCellHandlers(frame: Data) {
        var nextCell = true
        var data = buffer + frame
        buffer = Data(count: 0)
        
        while (nextCell) {
            // Load header
            let circuitId = protocolVersion < 4 ? UInt32(data.unpackInt(type: UInt16.self)) : data.unpackInt(type: UInt32.self)
            guard let command = CellCommand(rawValue: data.unpackInt(type: UInt8.self)) else {
                print("TorSocket: Failed to parse cell command")
                break
            }
//            print("TorSocket: Received \(command) cell for Circuit \(circuitId)")
            
            // Load payload
            var payloadLength = 509
            if isVariableLength(command: command) {
                payloadLength = Int(data.unpackInt(type: UInt16.self))
            }
            let frame = data.extract(in: 0..<payloadLength)
            
            
            // Load payload
            switch command {
            case .VERSIONS:
                notify(circuitId: circuitId, cell: CellVersions(circuitId: circuitId, frame: frame))
            case .CERTS:
                notify(circuitId: circuitId, cell: CellCerts(circuitId: circuitId, frame: frame))
            case .AUTH_CHALLENGE:
                notify(circuitId: circuitId, cell: CellAuthChallenge(circuitId: circuitId, frame: frame))
            case .NETINFO:
                notify(circuitId: circuitId, cell: CellNetInfo(circuitId: circuitId, frame: frame))
            case .CREATED2:
                notify(circuitId: circuitId, cell: CellCreated2(circuitId: circuitId, frame: frame))
            case .RELAY:
                notify(circuitId: circuitId, cell: CellRelay(circuitId: circuitId, frame: frame))
            case .DESTROY:
                if let cell = CellDestroy(circuitId: circuitId, frame: frame) {
                    print("TorSocket: Destroy Reason: \(cell.reason)")
                }
                self.close()
            default:
                break
            }
            
            if data.count < 514 {
                nextCell = false
                if data.count > 0 {
                    buffer += data
                    print("TorSocket: Remaining data. Count: \(data.count) Content: \(data.toHexString())")
                }
            }
        }
    }
    
    private func notify(circuitId: UInt32, cell: Cell) {
        guard let handler = cellHandlers[circuitId] else {
            print("TorSocket: No handler registered for circuitId: \(circuitId)")
            return
        }
        handler(cell)
    }
    
    private func isVariableLength(command: CellCommand) -> Bool {
        if command == .VERSIONS || command.rawValue >= 128 {
            return true
        } else {
            return false
        }
    }
    
}
