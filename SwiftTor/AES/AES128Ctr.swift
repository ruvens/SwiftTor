//
//  AES128Ctr.swift
//  Tor
//
//  Created by Ruven on 29.10.22.
//

import Foundation

final class AES128Ctr {
    
    public enum AESError: Error {
        case invalidKeySize
    }
    
    private let Rcon: [UInt8] = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
    ]
    
    private let Sbox: [UInt8] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]
    
    private var key: Data
    private var keyStream = Data(count: 0)
    private var counter: [UInt32]
    private lazy var keySchedule = self.generateKeySchedule()
    
    init (key: Data, iv: Data) throws {
        guard
            key.count == 16,
            iv.count == 16
        else {
            throw AESError.invalidKeySize
        }
        
        self.key = key
        self.counter = (0..<4).map { iv.unpackIntAt(type: UInt32.self, at: $0*4) }
    }
    
    @inlinable
    internal func rotateLeft(_ value: UInt32, by offset: Int) -> UInt32 {
        return ((value << offset) | (value >> (32 - offset)))
    }
    
    @inlinable
    internal func subWord(_ value: UInt32) -> UInt32 {
        var result: UInt32 = 0
        for i in 0..<4 {
            result += UInt32(Sbox[Int((value >> (24-i*8)) & 0xFF)]) << (24-i*8)
        }
        return result
    }
    
    @inlinable
    internal func gmul(_ a: UInt8) -> UInt8 {
        let result = (a << 1) & 0xFF
        if a < 128 {
            return result
        } else {
            return result ^ 0x1B
        }
    }
    
    @inlinable
    internal func shiftRows(_ values: [UInt32]) -> [UInt32] {
        var result = [UInt32](repeating: 0, count: 4)
        for i in 0..<4 {
            let offset = 24 - i * 8
            
            var b = [UInt32](repeating: 0, count: 4)
            b[0] = (values[0] >> offset) & 0xFF
            b[1] = (values[1] >> offset) & 0xFF
            b[2] = (values[2] >> offset) & 0xFF
            b[3] = (values[3] >> offset) & 0xFF
            
            result[(i*3) % 4] += b[0] << offset
            result[(i*3+1) % 4] += b[1] << offset
            result[(i*3+2) % 4] += b[2] << offset
            result[(i*3+3) % 4] += b[3] << offset
        }
        
        return result
    }
    
    @inlinable
    internal func mixColumns(_ value: UInt32) -> UInt32 {
        var result: UInt32 = 0
        
        let b0 = UInt8((value >> 24) & 0xFF)
        let b1 = UInt8((value >> 16) & 0xFF)
        let b2 = UInt8((value >> 8) & 0xFF)
        let b3 = UInt8(value & 0xFF)
        
        result += UInt32(gmul(b0) ^ gmul(b1) ^ b1 ^ b2 ^ b3) << 24
        result += UInt32(b0 ^ gmul(b1) ^ gmul(b2) ^ b2 ^ b3) << 16
        result += UInt32(b0 ^ b1 ^ gmul(b2) ^ gmul(b3) ^ b3) << 8
        result += UInt32(gmul(b0) ^ b0 ^ b1 ^ b2 ^ gmul(b3))
        
        return result
    }
    
    internal func generateKeySchedule() -> [UInt32] {
        var keySchedule = [UInt32](repeating: 0, count: 44)
        for i in 0..<4 {
            keySchedule[i] = key.unpackIntAt(type: UInt32.self, at: i*4)
        }
        
        var temp: UInt32
        for i in 4..<44 {
            temp = keySchedule[i-1] // 0c0d0e0f
            if (i % 4 == 0) {
                temp = subWord(rotateLeft(temp, by: 8)) ^ (UInt32(Rcon[i / 4]) << 24)
            }
            keySchedule[i] = keySchedule[i-4] ^ temp
        }
        
        return keySchedule
    }
    
    internal func encryptBlock(_ block: [UInt32]) -> Data {
        var message = block
        message = (0..<4).map { message[$0] ^ keySchedule[$0] }
        
        for round in 1..<10 {
            message = (0..<4).map { subWord(message[$0]) }
            message = shiftRows(message)
            message = (0..<4).map { mixColumns(message[$0]) }
            message = (0..<4).map { message[$0] ^ keySchedule[(round)*4+$0] }
        }
        
        message = (0..<4).map { subWord(message[$0]) }
        message = shiftRows(message)
        message = (0..<4).map { message[$0] ^ keySchedule[40+$0] }
        
        var result = Data()
        for i in 0..<4 {
           result += Swift.withUnsafeBytes(of: message[i].bigEndian) { Data($0) }
        }
        
        return result
    }
    
    internal func incrementCounter(_ counter: [UInt32]) -> [UInt32] {
        var result = counter
        for i in (0..<4).reversed() {
            if result[i] < UInt32.max {
                result[i] += 1
                return result
            }
        }
        return result
    }
    
    func apply(_ data: Data) -> Data {
        let blockCount = Int(ceil(Double(data.count - keyStream.count) / 16))
        for _ in 0..<blockCount {
            keyStream.append(encryptBlock(counter))
            counter = incrementCounter(counter)
        }
        
        return data ^ keyStream.extract(in: 0..<data.count)
    }
}
