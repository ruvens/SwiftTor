//
//  ContentView.swift
//  Tor
//
//  Created by Ruven on 29.10.22.
//

import SwiftUI
import WebKit

struct WebBrowserView: View {
    @State var webURL = "http://www.google.com"
    @State var htmlContent: String = ""
    let webView = WKWebView()
    
    var body: some View {
        VStack {
            HStack {
                TextField("URL:", text: $webURL)
                Button(action: loadWebsite) { Text("Load") }
            }
            Spacer()
            HTMLStringView(htmlContent: $htmlContent)
            Spacer()
        }
    }
    
    func loadWebsite() -> Void {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [
            kCFNetworkProxiesSOCKSEnable: true,
            kCFNetworkProxiesSOCKSPort: 1080,
            kCFNetworkProxiesSOCKSProxy: "localhost",
        ]
        let session = URLSession(configuration: config)
        
        session.dataTask(with: URL(string: webURL)!) { (data, response, error) in
            if let error = error {
                print("Error fetching google \(error.localizedDescription)")
                return
            }
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                print("Error httpResponse code")
                return
            }
            if let data = data {
                self.htmlContent = String(malformedUTF8: data)
            }
        }.resume()
    }
}

struct HTMLStringView: NSViewRepresentable {
    @Binding var htmlContent: String

    func makeNSView(context: Context) -> WKWebView {
        return WKWebView()
    }

    func updateNSView(_ uiView: WKWebView, context: Context) {
        uiView.loadHTMLString(htmlContent, baseURL: nil)
    }
}

