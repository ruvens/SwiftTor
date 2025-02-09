//
//  KeyAgreement.swift
//  Tor
//
//  Created by Ruven on 14.11.20.
//

import Foundation
import CryptoKit

protocol KeyAgreement {
    func getHandshake() -> Data
    func completeHandshake(serverKey: Data, auth: Data)
}

struct KeyAgreementNTOR: KeyAgreement {
    
    private let protocolId = "ntor-curve25519-sha256-1"
    private let tMac: String
    private let tKey: String
    private let tVerify: String
    private let mExpand: String
        
    private let handshake: Data
    
    private let router: OnionRouter
    private let nTorKey: Data
    
    private let privateKey: Curve25519.KeyAgreement.PrivateKey

    
    init?(router: OnionRouter) {
        self.tMac = protocolId + ":mac"
        self.tKey = protocolId + ":key_extract"
        self.tVerify = protocolId + ":verify"
        self.mExpand = protocolId + ":key_expand"
        
        self.router = router
        self.nTorKey = router.nTorKey
        
        privateKey = Curve25519.KeyAgreement.PrivateKey.init()
        let publicKey = privateKey.publicKey
        
        handshake = Data(Data(hex: router.identity) + nTorKey + publicKey.rawRepresentation)
    }
    
    func getHandshake() -> Data {
        return handshake
    }
    
    private func HMACSHA256(key: Data, data: Data) -> Data {
        let symKey = SymmetricKey.init(data: key)
        var hmac = CryptoKit.HMAC<SHA256>(key: symKey)
        hmac.update(data: data)
        return hmac.finalize().withUnsafeBytes { Data($0) }
    }
    
    private func HKDFRCF5869(ikm: Data, info: Data, salt: Data, outputBytes: Int) -> Data {
        let prk = HMACSHA256(key: salt, data: ikm)
        var out = Data(count: 0)
        var last = Data(count: 0)
        var i:UInt8 = 1
        
        while out.count < outputBytes {
            let m = last + info + withUnsafeBytes(of: i) { Data($0) }
            last = HMACSHA256(key: prk, data: m)
            out += last
            i += 1
        }
        
        return out.subdata(in: 0..<outputBytes)
    }
    
    func completeHandshake(serverKey: Data, auth: Data) {
        do {
            let serverX25519PK = try Curve25519.KeyAgreement.PublicKey.init(rawRepresentation: serverKey)
            let nTorKeyX25519PK = try Curve25519.KeyAgreement.PublicKey.init(rawRepresentation: nTorKey)
            
            var secretInput = try privateKey.sharedSecretFromKeyAgreement(with: serverX25519PK).withUnsafeBytes { Data($0) }
            secretInput += try privateKey.sharedSecretFromKeyAgreement(with: nTorKeyX25519PK).withUnsafeBytes { Data($0) }
            secretInput += Data(hex: router.identity)
            secretInput += nTorKey
            secretInput += self.privateKey.publicKey.rawRepresentation
            secretInput += serverKey
            secretInput += Data(protocolId.utf8)
            
            let verify = HMACSHA256(key: Data(tVerify.utf8), data: secretInput)
            
            var authInput = verify
            authInput += Data(hex: router.identity)
            authInput += nTorKey
            authInput += serverKey
            authInput += self.privateKey.publicKey.rawRepresentation
            authInput += Data(protocolId.utf8)
            authInput += Data("Server".utf8)
            
            let authDigest = HMACSHA256(key: Data(tMac.utf8), data: authInput)
            
            if auth == authDigest {
                print("KeyAgreementNTOR: Handshake complete. Authentication successful")
                
                let sharedSecret = HKDFRCF5869(ikm: secretInput, info: Data(mExpand.utf8), salt: Data(tKey.utf8), outputBytes: 72)
                try? router.setSharedSecret(secret: sharedSecret)
                
            } else {
                print("KeyAgreementNTOR: Server handshake does not match verification")
            }
        } catch {
            print(error.localizedDescription)
        }
    }
}

