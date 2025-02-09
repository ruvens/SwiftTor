//
//  TorManager.swift
//  Tor
//
//  Created by Ruven on 06.12.20.
//

import Foundation
import Network
import Socks5Proxy

class TorManager: TorService {

    let consensus = Consensus()
    private var socket: TorSocket? = nil
    private var circuit: Circuit? = nil
    var serviceStatus: TorServiceStatus = .offline
    
    func start() {
        let authority = consensus.getRandomDirectoryAuthority()
        print("TorManager: Using directory authority: \(authority.description)")
        consensus.loadRouterList(authority: authority)
        restart()
    }
    
    func restart() {
        let guardRelay = consensus.getRandomRouter(with: "guard")!
        print ("TorManager: Using guard relay: \(guardRelay.description)")
        socket = TorSocket(guardRelay: guardRelay)
        serviceStatus = .online
    }
    
    func buildCircuit(completion: @escaping (Circuit) -> Void) {
        let circuit = Circuit(socket: socket!)
        socket!.connect {
            circuit.create(guardRelay: self.socket!.guardRelay) {
                guard let extendRelay = self.consensus.getRandomRouter() else {
                    print("TorManager: Could not retrieve extend relay")
                    return
                }
                print ("TorManager: Extending Circuit \(circuit.circuitId) using middle relay: \(extendRelay.description)")
                circuit.extend(router: extendRelay) {
                    guard let exitRelay = self.consensus.getRandomRouter(with: "exit") else {
                        print("TorManager: Could not retrieve exit relay")
                        return
                    }
                    print ("TorManager: Extending Circuit \(circuit.circuitId) using exit relay: \(exitRelay.description)")
                    circuit.extend(router: exitRelay) {
                        self.circuit = circuit
                        completion(circuit)
                    }
                }
            }
        }
    }
    
    func getSocksStreamsHandler(endpoint: NWEndpoint, completion: @escaping (SocksStreamHandler) -> Void) {
        guard case .hostPort(let host, let port) = endpoint else {
            print("TorManager: Could not resolve NWEndpoint")
            return
        }
        print("TorManager: Attempting to retrieve a Tor stream ...")
        getTorStream(host: host.debugDescription, port: port.rawValue) { stream in
            completion(stream)
        }
    }
    
    func getTorStream(host: String, port: UInt16, completion: @escaping (Stream) -> Void) {
        print("TorManager: GetTorStream triggered")
        guard let socket = socket,
            isSocketOnline() else {
            print("TorManager: Requested Stream but not active socket. Attempting to restart ...")
            restart()
            getTorStream(host: host, port: port, completion: completion)
            return
        }
        
        socket.connect {
            if let circuit = self.circuit,
               case .extended = circuit.status {
                print("TorManager: Retrieving stream from exisiting circuit \(circuit.circuitId)")
                self.getStream(host: host, port: port, circuit: circuit, completion: completion)
            } else {
                self.buildCircuit { circuit in
                    print("TorManager: Retrieving stream from newly created circuit \(circuit.circuitId)")
                    self.getStream(host: host, port: port, circuit: circuit, completion: completion)
                }
            }
        }
    }
    
    private func getStream(host: String, port: UInt16, circuit: Circuit, completion: @escaping (Stream) -> Void) {
        let stream = Stream(circuit: circuit)
        stream.create(host: host, port: port) {
            completion(stream)
        }
    }
    
    private func isSocketOnline() -> Bool {
        guard let socket = socket,
              socket.status != .closed else {
            self.socket = nil
            self.circuit = nil
            return false
        }
        return true
    }
    
    private func isCircuitOnline() -> Bool {
        
        guard let circuit = circuit else {
            self.circuit = nil
            return false
        }
        
        if case .closed = circuit.status {
            self.circuit = nil
            return false
        } else {
            return true
        }
    }
    
}
