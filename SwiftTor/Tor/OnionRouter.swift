//
//  OnionRouter.swift
//  Tor
//
//  Created by Ruven on 10.11.20.
//

import Foundation
import CryptoKit

class OnionRouter {
    
    class CryptoBox {
        var forwardDigest: Data
        var backwardDigest: Data
        var encryptionKey: Data
        var decryptionKey: Data
        
        var encryptor: AES128Ctr
        var decryptor: AES128Ctr
                        
        init(from secret: Data) throws {
            var data = secret
            forwardDigest = data.extract(in: 0..<20)
            backwardDigest = data.extract(in: 0..<20)
            encryptionKey = data.extract(in: 0..<16)
            decryptionKey = data.extract(in: 0..<16)
            
            encryptor = try AES128Ctr(key: encryptionKey, iv: Data(count: 16))
            decryptor = try AES128Ctr(key: decryptionKey, iv: Data(count: 16))

        }
        
        func getDigest(data: Data) -> Data {
            forwardDigest += data
            return Data(Insecure.SHA1.hash(data: forwardDigest))
        }
        
        func checkDigest(data: Data) -> Bool {
            var frame = data
            let readDigest = frame.subdata(in: 5..<9)
            frame.replaceSubrange(5..<9, with: Data(count: 4))
            
            backwardDigest += frame
//            print("CryptoBox: calc digest: \(Data(Insecure.SHA1.hash(data: backwardDigest)).toHexString()), read digest: \(readDigest.toHexString())")
            let calcDigest = Data(Insecure.SHA1.hash(data: backwardDigest)).subdata(in: 0..<4)
            return calcDigest == readDigest
        }
        
        func getBackwardDigest() -> Data {
            return Data(Insecure.SHA1.hash(data: backwardDigest))
        }
        
        func encrypt(relayPayload: Data) -> Data {
            return encryptor.apply(relayPayload)
        }
        
        func decrypt(relayPayload: Data) -> Data {
            return decryptor.apply(relayPayload)
        }
    }
    
    let name: String
    let identity: String
    let ip: String
    let dirPort: UInt16
    let torPort: UInt16
    let nTorKey: Data
    let digest: Data
    
    var flags: [String]? = nil
    var crypto: CryptoBox? = nil

    var description: String {
        return "\(name)@\(ip) (tor):\(torPort) (dir):\(dirPort) | id: \(identity), flags: \(flags ?? [""]), digest: \(digest.toHexString()), nTorKey: \(nTorKey.toHexString())"
    }
    
    init(name: String, identity: String, ip: String, dirPort: UInt16, torPort: UInt16, nTorKey: Data, digest: Data) {
        self.name = name
        self.identity = identity
        self.ip = ip
        self.dirPort = dirPort
        self.torPort = torPort
        self.nTorKey = nTorKey
        self.digest = digest
    }
    
    func setSharedSecret(secret: Data) throws {
        crypto = try CryptoBox(from: secret)
    }
    
}
