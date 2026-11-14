import Foundation

extension FileHandle {

    public var pidOfConnectedProcess: Int32 {
        var pid: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        guard unsafe getsockopt(fileDescriptor, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0,
              len == MemoryLayout<Int32>.size, pid > 0 else { return 0 }
        return pid
    }

}
