//
//  String+Extensions.swift
//  Tor
//
//  Created by Ruven on 29.10.22.
//

import Foundation

extension String {
    init(malformedUTF8 data: Data) {
        var data = data
        data.append(0)
        self = data.withUnsafeBytes{ p in
            String(cString: p.bindMemory(to: CChar.self).baseAddress!)
        }.replacingOccurrences(of: "\u{FFFD}", with: "")
    }
}
