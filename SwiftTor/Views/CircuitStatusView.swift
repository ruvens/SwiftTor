//
//  CircuitStatusView.swift
//  Tor
//
//  Created by Ruven on 29.10.22.
//

import SwiftUI

struct CircuitUIInformation: Identifiable {
    let id = UUID()
    let circuitId: String
    let exitName: String
    let streamNumber: String
}

struct CircuitStatusView: View {
    
    private var circuitStore = [
        CircuitUIInformation(circuitId: "121384", exitName: "bastion18", streamNumber: "9"),
        CircuitUIInformation(circuitId: "121384", exitName: "bastion18", streamNumber: "9"),
        CircuitUIInformation(circuitId: "121384", exitName: "bastion18", streamNumber: "9"),
        CircuitUIInformation(circuitId: "121384", exitName: "bastion18", streamNumber: "9")
    ]
    
    var body: some View {
        Table(circuitStore) {
            TableColumn("Circuit Id", value: \.circuitId)
            TableColumn("Exit Node Name", value: \.exitName)
            TableColumn("Stream Number", value: \.streamNumber)
        }
    }
}
