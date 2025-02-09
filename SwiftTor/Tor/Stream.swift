//
//  Stream.swift
//  Tor
//
//  Created by Ruven on 29.11.20.
//

import Foundation
import Network
import Socks5Proxy

class Stream: SocksStreamHandler {
    
    enum StreamStatus {
        case connecting
        case connected
        case closed
    }
    
    let streamId: UInt16
    var status: StreamStatus = .connecting
    
    weak var circuit: Circuit?
    
    var cancellationHandler: (() -> Void)? = nil
    var relayDataHandler: ((Data) -> Void)? = nil
    private var connectionListeners: [() -> Void] = []
    
    private let window = TorWindow(size: 500, increment: 50)
    
    init(circuit: Circuit) {
        streamId = UInt16.random(in: 1..<65535)
        print("Stream \(self.streamId): Created stream")
        self.circuit = circuit
        setupRelayCellHandler()
    }
    
    func start(completion: @escaping () -> Void) {
        print("Stream: started")
        completion()
    }
    
    deinit {
        print("Stream \(self.streamId): Deinitializing stream")
    }
    
    private func setupRelayCellHandler() {
        circuit?.registerRelayCellHandler(with: streamId) { [weak self] cell in
            print("Stream \(self?.streamId ?? 0): Received cell \(cell.command). (deliver = \(self?.window.deliverWindow), package = \(self?.window.packageWindow))")
            switch cell.command {
            case .CONNECTED:
                if case .connecting = self?.status {
                    let connectedCell = cell as! RelayCellConnected
                    print("Stream \(self?.streamId ?? 0): Connected to \(connectedCell.address) for time \(connectedCell.ttl)")
                    self?.status = .connected
                    self?.connectionListeners.forEach { $0() }
                    self?.connectionListeners.removeAll()
                } else {
                    print("Stream \(self?.streamId ?? 0): Received Relay CONNECTED cell but in status \(String(describing: self?.status))")
                }
            case .DATA:
                if let sendMeRequired = self?.window.receivedData(),
                   sendMeRequired {
                    print("Stream \(self?.streamId ?? 0): Incremented deliver window")
                    self?.window.deliveredSendMe()
                    self?.circuit?.sendSendMe(streamId: self!.streamId) {
                        return
                    }
                }
                if case .connected = self?.status {
                    let dataCell = cell as! RelayCellData
                    guard let handler = self?.relayDataHandler else {
                        print("Stream \(self?.streamId ?? 0): Data received, but no RelayDataHandler set")
                        return
                    }
                    print("Stream \(self?.streamId ?? 0): Received Relay DATA cell. Window (deliver = \(self!.window.deliverWindow), package = \(self!.window.packageWindow))")
                    //try? self?.appendFile(data: dataCell.data)
                    handler(dataCell.data)
                } else {
                    print("Stream \(self?.streamId ?? 0): Received Relay DATA cell but in status \(String(describing: self?.status))")
                }
            case .SENDME:
                print("Stream: Received Relay SENDME cell")
                self?.window.receivedSendMe()
            case .END:
                let endCell = cell as! RelayCellEnd
                self?.status = .closed
                self?.circuit?.removeRelayCellHandler(with: self!.streamId)
                print("Stream \(self?.streamId ?? 0): Received Relay END cell with reason: \(String(describing: endCell.reason))")
            case .TRUNCATED:
                let truncCell = cell as! RelayCellTruncated
                self?.status = .closed
                self?.circuit?.removeRelayCellHandler(with: self!.streamId)
                print("Stream \(self?.streamId ?? 0): Received Relay TRUNCATED cell with reason: \(String(describing: truncCell.reason))")
            default:
                break
            }
        }
    }
    
    func create(host: String, port: UInt16, completion: @escaping () -> Void) {
        if status == .connected {
            completion()
        } else {
            connectionListeners.append(completion)
            print("Stream \(self.streamId): Send Relay BEGIN cell")
            circuit?.sendRelayCell(cell: RelayCellBegin(streamId: streamId, host: host, port: port))
        }
    }
    
    func relay(data: Data) {
        var frame = data
        while (frame.count > 0) {
            print("Stream \(self.streamId): Send data \(frame.count)")
            let length = min(frame.count, 498)
            let sendFrame = frame.unpackData(count: length)
            if window.authorizeSend() {
                print("Stream \(self.streamId): Send Relay DATA cell")
                circuit?.sendRelayCell(cell: RelayCellData(streamId: streamId, frame: sendFrame))
            } else {
                print("Stream \(self.streamId): Authorization to relay data cell declined. Insufficient package window count")
            }
        }
    }
    
    func stop() {
        
    }
    
    func appendFile(data: Data) throws {
        let dir: URL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).last! as URL
        let url = dir.appendingPathComponent("torsite.html")
        if let fileHandle = try? FileHandle(forWritingTo: url) {
            defer {
                fileHandle.closeFile()
            }
            fileHandle.seekToEndOfFile()
            fileHandle.write(String(malformedUTF8: data).data(using: .utf8)!)
        } else {
            print("Could not write")
        }
    }
    
}
