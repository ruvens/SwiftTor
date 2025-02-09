//
//  NavigationView.swift
//  Tor
//
//  Created by Ruven on 30.10.22.
//

import SwiftUI

struct SidebarView: View {
    
    let torService: TorService
    
    @State private var torServiceStatus: TorServiceStatus = .offline

    var body: some View {
        VStack {
            List {
                NavigationLink("Circuits", destination: CircuitStatusView())
            }
            
            switch torServiceStatus {
            case .offline:
                Button(action: {
                    torService.start()
                    torServiceStatus = .online
                }, label: {
                    Label(title: { Text("Service Offline") }, icon: { Image(systemName: "circle.fill").foregroundColor(.red) })
                })
            case .online:
                Label(title: { Text("Service Online") }, icon: { Image(systemName: "circle.fill").foregroundColor(.green) })
            }
            
        }.padding([.bottom, .top], 10)
    }
    
    init(torService: TorService) {
        self.torService = torService
    }
}
