//
//  Consensus.swift
//  Tor
//
//  Created by Ruven on 10.11.20.
//

import Foundation

class Consensus {
    
    private let directoryAuthorities: [DirectoryAuthority]
    private var routerList: [OnionRouter] = []

    init() {
        directoryAuthorities = [
            DirectoryAuthority(name: "Serge", ip: "66.111.2.131", dirPort: 9030, torPort: 9001),
            DirectoryAuthority(name: "tor26", ip: "217.196.147.77", dirPort: 80, torPort: 443),
            DirectoryAuthority(name: "longclaw", ip: "199.58.81.140", dirPort: 80, torPort: 443),
            DirectoryAuthority(name: "dizum", ip: "45.66.35.11", dirPort: 80, torPort: 443),
            DirectoryAuthority(name: "bastet", ip: "204.13.164.118", dirPort: 80, torPort: 443),
            DirectoryAuthority(name: "gabelmoo", ip: "131.188.40.189", dirPort: 80, torPort: 443),
            DirectoryAuthority(name: "moria1", ip: "128.31.0.39", dirPort: 9231, torPort: 9201),
            DirectoryAuthority(name: "dannenberg", ip: "193.23.244.244", dirPort: 80, torPort: 443),
            DirectoryAuthority(name: "faravahar", ip: "216.218.219.41", dirPort: 80, torPort: 443)
        ]
    }
    
    func getRandomDirectoryAuthority() -> DirectoryAuthority {
        return directoryAuthorities.randomElement()!
    }
    
    func getRandomRouter(with flag: String) -> OnionRouter? {
        return routerList.filter({
            $0.flags != nil && $0.flags!.contains(flag)
        }).randomElement()
    }
    
    func getRandomRouter() -> OnionRouter? {
        return routerList.randomElement()
    }
    
    func loadNTorKey(serverDescriptorURL: URL) -> Data? {
        let session = URLSession(configuration: URLSessionConfiguration.ephemeral)
        
        let (odata, _, _) = session.synchronousDataTask(with: serverDescriptorURL)
        guard let data = odata,
              let info = String(bytes: data, encoding: String.Encoding.utf8) else {
            print("Consensus: Failed to access \(serverDescriptorURL.absoluteString)")
            return nil
        }
        
        var nTorKey: Data? = nil
        info.enumerateLines { (line, _) in
            if line.starts(with: "ntor-onion-key ") {
                let elements = line.components(separatedBy: " ")
                nTorKey = Data(base64UnpaddedString: elements[1])
                return
            }
        }
        return nTorKey
    }

    func loadRouterList(authority: DirectoryAuthority , limit: Int = 50) {
        let consensusURL = authority.getConsensusURL()
        let session = URLSession(configuration: URLSessionConfiguration.ephemeral)
        
        print("Consensus: Loading router list from \(consensusURL)")
        let (odata, _, _) = session.synchronousDataTask(with: consensusURL)
        guard let data = odata,
              let info = String(bytes: data, encoding: String.Encoding.utf8) else {
            print("Consensus: Failed to access \(consensusURL.absoluteString)")
            return
        }
        
        var numOnionRouters = 0
        var onionRouters: [OnionRouter] = []
        var onionRouter: OnionRouter? = nil
        
        info.enumerateLines { (line, _) in
            guard numOnionRouters < limit else {
                return
            }
            
            if line.starts(with: "r ") {
                let elements = line.components(separatedBy: " ")
                
                if let digest = Data(base64UnpaddedString: elements[3]),
                   let nTorKey = self.loadNTorKey(serverDescriptorURL: authority.getServerDescURL(digest: digest.toHexString())),
                   let id = Data(base64UnpaddedString: elements[2]),
                   let dirPort = UInt16(elements[8]),
                   let torPort = UInt16(elements[7]) {
                    onionRouter = OnionRouter(name: elements[1], identity: id.toHexString(), ip: elements[6], dirPort: dirPort, torPort: torPort, nTorKey: nTorKey, digest: digest)
                }

            } else if line.starts(with: "s ") {
                if let router = onionRouter {
                    
                    var flags = line.components(separatedBy: " ").map { $0.lowercased() }
                    flags.removeFirst()
                    
                    if ["fast", "valid", "running"].allSatisfy(flags.contains) {
                        numOnionRouters += 1
                        router.flags = flags
                        onionRouters.append(router)
                    }
                    
                    onionRouter = nil
                }
            }
        }
        
        routerList = onionRouters
//        for r in routerList {
//            print("Consensus: \(r.description)")
//        }
        print("Consensus: Loaded \(routerList.count) onion routers")
    }
    
}

struct DirectoryAuthority {
    
    let name: String
    let ip: String
    let dirPort: UInt16
    let torPort: UInt16
    
    var description: String {
        return "\(name)@\(ip) (tor):\(torPort) (dir):\(dirPort)"
    }
    
    func getConsensusURL() -> URL {
        return URL(string: "http://\(ip):\(dirPort)/tor/status-vote/current/consensus")!
        //http://193.23.244.244:80/tor/status-vote/current/consensus
    }
    
    func getServerDescURL(digest: String) -> URL {
        return URL(string: "http://\(ip):\(dirPort)/tor/server/d/\(digest)")!
        //http://45.66.35.11:80/tor/server/d/6d283f6d4a06ac76c2b2601fa8490999a013b8d6
    }
    
}
