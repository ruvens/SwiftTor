//
//  URLSession+Extensions.swift
//  Tor
//
//  Created by Ruven on 29.10.22.
//

import Foundation

extension URLSession {
    
    func synchronousDataTask(with url: URL) -> (Data?, URLResponse?, Error?) {
        var data: Data?
        var response: URLResponse?
        var error: Error?
        
        let semaphore = DispatchSemaphore(value: 0)
        
        self.dataTask(with: url) {
            data = $0
            response = $1
            error = $2
            
            semaphore.signal()
        }.resume()
        
        _ = semaphore.wait(timeout: .distantFuture)

        return (data, response, error)
    }
    
}
