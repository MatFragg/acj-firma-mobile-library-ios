import Foundation
import os.log

public class LogManager {
    public static let subsystem = "com.acj.firma"

    public enum LogType: String {
        case info = "INFO"
        case warning = "WARNING"
        case error = "ERROR"
    }

    public static func log(_ type: LogType, _ message: String, category: String = "firma-lib-log") {
        let log = OSLog(subsystem: subsystem, category: category)
        switch type {
        case .info:
            os_log(.info, log: log, "%{public}@", message)
        case .warning:
            os_log(.default, log: log, "%{public}@", message)
        case .error:
            os_log(.error, log: log, "%{public}@", message)
        }
    }

    public static func info(_ message: String, category: String = "firma-lib-log") {
        log(.info, message, category: category)
    }

    public static func warning(_ message: String, category: String = "firma-lib-log") {
        log(.warning, message, category: category)
    }

    public static func error(_ message: String, category: String = "firma-lib-log") {
        log(.error, message, category: category)
    }
}
