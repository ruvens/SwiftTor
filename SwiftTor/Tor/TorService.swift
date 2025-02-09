//
//  TorService.swift
//  Tor
//
//  Created by Ruven on 30.10.22.
//

import Foundation
import Network
import Socks5Proxy

enum TorServiceStatus {
    case online
    case offline
}

protocol TorService: SocksStreamProvider {
    var serviceStatus: TorServiceStatus { get }
    
    func start()
}
