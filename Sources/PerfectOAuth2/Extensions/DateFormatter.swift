//
//  DateFormatter.swift
//  PerfectTemplate
//
//  Created by Bas van Kuijck on 10/02/2017.
//
//

import Foundation

extension DateFormatter {
    public static var mySQL: DateFormatter {
        let df = DateFormatter()
        df.dateFormat = "YYYY-MM-dd HH:mm:ss ZZZ"
        return df
    }
}
