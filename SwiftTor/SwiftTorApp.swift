//
//  SwiftTorApp.swift
//  SwiftTor
//
//  Created by Ruven Schneider on 09.02.25.
//

import SwiftUI
import Socks5Proxy

@main
struct SwiftTorApp: App {
    
    let proxyManager: SocksProxyManager
    let torService: TorManager
    
    var body: some Scene {
        WindowGroup("Tor Browser", id: "browser") {
            WebBrowserView()
        }
    }
    
    init() {
        torService = TorManager()
        proxyManager = try! SocksProxyManager(streamProvider: torService)
        torService.start()
    }
}
