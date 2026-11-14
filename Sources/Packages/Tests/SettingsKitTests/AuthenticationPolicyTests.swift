import Foundation
import Testing
import SettingsKit

@Suite struct AuthenticationPolicyTests {

    @Test func defaultsRequireAuthentication() throws {
        let policy = AuthenticationPolicy()
        #expect(!policy.allowGitReads)
        #expect(policy.programs.isEmpty)
        #expect(try JSONDecoder().decode(AuthenticationPolicy.self, from: JSONEncoder().encode(policy)) == policy)
    }

    @Test(arguments: [
        ["git", "fetch"], ["git", "pull", "--rebase"],
        ["git", "-C", "/tmp/project", "fetch", "origin"],
        ["git", "-c", "core.sshCommand=/usr/bin/ssh", "--no-pager", "pull"],
        ["git", "--git-dir=/tmp/repo/.git", "fetch"],
        ["git", "--work-tree", "/tmp/fetch", "-C/tmp/repo", "fetch"],
    ]) func recognizesReadCommands(_ arguments: [String]) {
        #expect(GitReadCommand.matches(arguments))
    }

    @Test(arguments: [
        [], ["git"], ["git", "push"], ["git", "commit"], ["git", "status"],
        ["git", "-c", "alias.f=fetch", "f"], ["git", "push", "fetch"],
        ["git", "--unknown", "fetch"], ["git", "--exec-path=/tmp", "fetch"],
        ["git", "-C"], ["git", "-C", "fetch"], ["git", "-c", "", "fetch"],
        ["git", "--git-dir=", "fetch"], ["git", "--", "fetch"],
        ["git", "fetch-and-push"], ["git", "-C", "fetch", "push"],
    ]) func rejectsOtherCommands(_ arguments: [String]) {
        #expect(!GitReadCommand.matches(arguments))
    }

    @Test func decodesKernelArgumentsWithoutEnvironment() {
        let arguments = ["/usr/bin/git", "-C", "/tmp/repo", "fetch", ""]
        let bytes = kernelArguments(arguments) + Array("PRIVATE_VALUE=do-not-retain\0".utf8)
        #expect(ProcessArguments.decode(bytes) == arguments)
    }

    @Test func rejectsInvalidKernelArguments() {
        #expect(ProcessArguments.decode([]) == nil)
        #expect(ProcessArguments.decode([0, 0, 0, 0, 1, 0]) == nil)
        #expect(ProcessArguments.decode([255, 255, 255, 255, 1, 0]) == nil)
        #expect(ProcessArguments.decode(Array(kernelArguments(["git", "fetch"]).dropLast())) == nil)
        #expect(ProcessArguments.decode([UInt8](repeating: 1, count: ProcessArguments.maximumBytes + 1)) == nil)
        #expect(ProcessArguments.decode([1, 0, 0, 0, 47, 0, 0, 255, 0]) == nil)
    }

    private func kernelArguments(_ arguments: [String]) -> [UInt8] {
        [UInt8(arguments.count), 0, 0, 0] + Array("/usr/bin/git\0\0\0".utf8) + arguments.flatMap { Array($0.utf8) + [0] }
    }
}
