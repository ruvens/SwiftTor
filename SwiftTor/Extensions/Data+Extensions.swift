//
//  Data+Extensions.swift
//  Tor
//
//  Created by Ruven on 29.10.22.
//

import Foundation

extension Data {
    public static func ^ (lhs: Data, rhs: Data) -> Data {
        return Data((0..<Swift.min(lhs.count, rhs.count)).map { lhs[$0] ^ rhs[$0] })
    }
    
    public init?(base64UnpaddedString: String) {
        self.init(base64Encoded: base64UnpaddedString + String(repeating: "=", count: ((4 - (base64UnpaddedString.count % 4)) % 4) ))
    }
    
    public init(hex: String) {
        self.init(Array<UInt8>(hex: hex))
    }
    
    public var bytes: Array<UInt8> {
        Array(self)
    }
    
    public func toHexString() -> String {
        self.bytes.toHexString()
    }
    
    mutating func extract(in range: Range<Data.Index>) -> Data {
        precondition(range.endIndex <= self.count, "Index out of bounds")
        let extracted = self.subdata(in: range)
        self.removeSubrange(range)
        return extracted
    }
    
    mutating func unpackInt<T: FixedWidthInteger>(type: T.Type) -> T {
        return self.extract(in: 0..<(type.bitWidth / 8)).withUnsafeBytes {
            $0.load(as: type)
        }.bigEndian
    }
    
    mutating func unpackData(count: Int) -> Data {
        return self.extract(in: 0..<count)
    }
    
    mutating func packInt<T: FixedWidthInteger>(_ value: T) {
        self += Swift.withUnsafeBytes(of: value.bigEndian) { Data($0) }
    }
    
    mutating func packData(_ data: Data) {
        self += data
    }
    
    init?(ip: String) {
        var addr = in_addr()
        if inet_pton(AF_INET, ip, &addr) == 1 {
            self = Swift.withUnsafeBytes(of: addr.s_addr) { Data($0) }
        } else {
            var addr6 = in6_addr()
            if inet_pton(AF_INET6, ip, &addr6) == 1 {
                self = Swift.withUnsafeBytes(of: addr6) { Data($0) }
            } else {
                return nil
            }
        }
    }
    
    func toIpString() -> String? {
        if self.count == 4 {
            return "\(self[0]).\(self[1]).\(self[2]).\(self[3])"
        } else if self.count == 16 {
            var ipString = self.toHexString()
            guard ipString.count == 32 else {
                return nil
            }
            for i in 1..<8 {
                ipString.insert(":", at: String.Index(utf16Offset: 5*i-1, in: ipString))
            }
            return ipString
        } else {
            return nil
        }
    }
    
    func unpackIntAt<T: FixedWidthInteger>(type: T.Type, at startIndex: Int) -> T {
        let remainingBytes = self.count - startIndex
        let byteWidth = type.bitWidth / 8
        
        guard remainingBytes > byteWidth else {
            var paddedData = self
            paddedData.append(Data(repeating: 0, count: byteWidth-remainingBytes))
            return paddedData[startIndex..<(startIndex + byteWidth)].withUnsafeBytes {
                $0.load(as: type)
            }.bigEndian
        }
        
        return self[startIndex..<(startIndex + byteWidth)].withUnsafeBytes {
            $0.load(as: type)
        }.bigEndian
    }
}
