//number of apis 73
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("os").getMember("system") and qn = "os.system" or
  api = API::moduleImport("os").getMember("popen") and qn = "os.popen" or
  api = API::moduleImport("os").getMember("spawnl") and qn = "os.spawnl" or
  api = API::moduleImport("os").getMember("spawnle") and qn = "os.spawnle" or
  api = API::moduleImport("os").getMember("spawnlp") and qn = "os.spawnlp" or
  api = API::moduleImport("os").getMember("spawnlpe") and qn = "os.spawnlpe" or
  api = API::moduleImport("os").getMember("spawnv") and qn = "os.spawnv" or
  api = API::moduleImport("os").getMember("spawnve") and qn = "os.spawnve" or
  api = API::moduleImport("os").getMember("spawnvp") and qn = "os.spawnvp" or
  api = API::moduleImport("os").getMember("spawnvpe") and qn = "os.spawnvpe" or
  api = API::moduleImport("os").getMember("posix_spawn") and qn = "os.posix_spawn" or
  api = API::moduleImport("os").getMember("posix_spawnp") and qn = "os.posix_spawnp" or
  api = API::moduleImport("os").getMember("execl") and qn = "os.execl" or
  api = API::moduleImport("os").getMember("execle") and qn = "os.execle" or
  api = API::moduleImport("os").getMember("execlp") and qn = "os.execlp" or
  api = API::moduleImport("os").getMember("execlpe") and qn = "os.execlpe" or
  api = API::moduleImport("os").getMember("execv") and qn = "os.execv" or
  api = API::moduleImport("os").getMember("execve") and qn = "os.execve" or
  api = API::moduleImport("os").getMember("execvp") and qn = "os.execvp" or
  api = API::moduleImport("os").getMember("execvpe") and qn = "os.execvpe" or
  api = API::moduleImport("subprocess").getMember("run") and qn = "subprocess.run" or
  api = API::moduleImport("subprocess").getMember("call") and qn = "subprocess.call" or
  api = API::moduleImport("subprocess").getMember("check_output") and qn = "subprocess.check_output" or
  api = API::moduleImport("subprocess").getMember("Popen") and qn = "subprocess.Popen" or
  api = API::moduleImport("subprocess").getMember("check_call") and qn = "subprocess.check_call" or
  api = API::moduleImport("subprocess").getMember("getoutput") and qn = "subprocess.getoutput" or
  api = API::moduleImport("subprocess").getMember("getstatusoutput") and qn = "subprocess.getstatusoutput" or
  api = API::moduleImport("subprocess").getMember("list2cmdline") and qn = "subprocess.list2cmdline" or
  api = API::moduleImport("pty").getMember("spawn") and qn = "pty.spawn" or
  api = API::moduleImport("invoke").getMember("run") and qn = "invoke.run" or
  api = API::moduleImport("shlex").getMember("split") and qn = "shlex.split" or
  api = API::moduleImport("asyncio").getMember("create_subprocess_exec") and qn = "asyncio.create_subprocess_exec" or
  api = API::moduleImport("asyncio").getMember("create_subprocess_shell") and qn = "asyncio.create_subprocess_shell" or
  api = API::moduleImport("shutil").getMember("which") and qn = "shutil.which" or
  api = API::moduleImport("distutils").getMember("spawn").getMember("find_executable") and qn = "distutils.spawn.find_executable" or
  api = API::moduleImport("pexpect").getMember("spawn") and qn = "pexpect.spawn" or
  api = API::moduleImport("pexpect").getMember("run") and qn = "pexpect.run" or
  api = API::moduleImport("psutil").getMember("Popen") and qn = "psutil.Popen" or
  api = API::moduleImport("paramiko").getMember("SSHClient").getAnInstance().getMember("exec_command") and qn = "paramiko.SSHClient.exec_command" or
  api = API::moduleImport("fabric").getMember("Connection").getAnInstance().getMember("run") and qn = "fabric.Connection.run" or
  api = API::moduleImport("fabric").getMember("Connection").getAnInstance().getMember("sudo") and qn = "fabric.Connection.sudo" or
  api = API::moduleImport("fabric").getMember("Connection").getAnInstance().getMember("local") and qn = "fabric.Connection.local" or
  api = API::moduleImport("invoke").getMember("Context").getAnInstance().getMember("run") and qn = "invoke.Context.run" or
  api = API::moduleImport("twisted").getMember("internet").getMember("utils").getMember("getProcessOutput") and qn = "twisted.internet.utils.getProcessOutput" or
  api = API::moduleImport("twisted").getMember("internet").getMember("utils").getMember("getProcessOutputAndValue") and qn = "twisted.internet.utils.getProcessOutputAndValue" or
  api = API::moduleImport("twisted").getMember("internet").getMember("reactor").getMember("spawnProcess") and qn = "twisted.internet.reactor.spawnProcess" or
  api = API::moduleImport("trio").getMember("run_process") and qn = "trio.run_process" or
  api = API::moduleImport("anyio").getMember("run_process") and qn = "anyio.run_process" or
  api = API::moduleImport("plumbum").getMember("local") and qn = "plumbum.local" or
  api = API::moduleImport("plumbum").getMember("cmd") and qn = "plumbum.cmd" or
  api = API::moduleImport("airflow").getMember("operators").getMember("bash").getMember("BashOperator") and qn = "airflow.operators.bash.BashOperator" or
  api = API::moduleImport("luigi").getMember("contrib").getMember("external_program").getMember("ExternalProgramTask") and qn = "luigi.contrib.external_program.ExternalProgramTask" or
  api = API::moduleImport("sh").getMember("Command") and qn = "sh.Command" or
  api = API::moduleImport("sh").getMember("bash") and qn = "sh.bash" or
  api = API::moduleImport("shlex").getMember("quote") and qn = "shlex.quote" or
  api = API::moduleImport("pipes").getMember("quote") and qn = "pipes.quote" or
  api = API::moduleImport("shlex").getMember("join") and qn = "shlex.join" or
  api = API::moduleImport("gevent").getMember("subprocess").getMember("Popen") and qn = "gevent.subprocess.Popen" or
  api = API::moduleImport("delegator").getMember("run") and qn = "delegator.run" or
  api = API::moduleImport("plumbum").getMember("SshMachine") and qn = "plumbum.SshMachine" or
  api = API::moduleImport("fabric").getMember("Group").getAnInstance().getMember("run") and qn = "fabric.Group.run" or
  api = API::moduleImport("twisted").getMember("internet").getMember("utils").getMember("getProcessValue") and qn = "twisted.internet.utils.getProcessValue" or
  api = API::moduleImport("asyncssh").getMember("SSHClientConnection").getAnInstance().getMember("run") and qn = "asyncssh.SSHClientConnection.run" or
  api = API::moduleImport("winrm").getMember("Session").getAnInstance().getMember("run_cmd") and qn = "winrm.Session.run_cmd" or
  api = API::moduleImport("winrm").getMember("Session").getAnInstance().getMember("run_ps") and qn = "winrm.Session.run_ps" or
  api = API::moduleImport("pexpect").getMember("spawnu") and qn = "pexpect.spawnu" or
  api = API::moduleImport("pexpect").getMember("runu") and qn = "pexpect.runu" or
  api = API::moduleImport("wmi").getMember("WMI").getAnInstance().getMember("Win32_Process").getMember("Create") and qn = "wmi.WMI.Win32_Process.Create" or
  api = API::moduleImport("win32api").getMember("ShellExecute") and qn = "win32api.ShellExecute" or
  api = API::moduleImport("win32com").getMember("shell").getMember("shell").getMember("ShellExecuteEx") and qn = "win32com.shell.shell.ShellExecuteEx" or
  api = API::moduleImport("win32com").getMember("shell").getMember("ShellExecuteEx") and qn = "win32com.shell.ShellExecuteEx" or
  api = API::moduleImport("win32process").getMember("CreateProcess") and qn = "win32process.CreateProcess" or
  api = API::moduleImport("win32process").getMember("CreateProcessAsUser") and qn = "win32process.CreateProcessAsUser" or
  api = API::moduleImport("os").getMember("popen2") and qn = "os.popen2" or
  api = API::moduleImport("os").getMember("popen3") and qn = "os.popen3" or
  api = API::moduleImport("os").getMember("popen4") and qn = "os.popen4" or
  api = API::moduleImport("os").getMember("startfile") and qn = "os.startfile" or
  api = API::moduleImport("fabric").getMember("api").getMember("run") and qn = "fabric.api.run" or
  api = API::moduleImport("fabric").getMember("api").getMember("local") and qn = "fabric.api.local" or
  api = API::moduleImport("fabric").getMember("api").getMember("sudo") and qn = "fabric.api.sudo" or
  api = API::moduleImport("airflow").getMember("providers").getMember("ssh").getMember("operators").getMember("ssh").getMember("SSHOperator") and qn = "airflow.providers.ssh.operators.ssh.SSHOperator" or
  api = API::moduleImport("prefect").getMember("tasks").getMember("shell").getMember("ShellTask") and qn = "prefect.tasks.shell.ShellTask" or
  api = API::moduleImport("prefect_shell").getMember("commands").getMember("run_shell_command") and qn = "prefect_shell.commands.run_shell_command" or
  api = API::moduleImport("delegator").getMember("cmd") and qn = "delegator.cmd" or
  api = API::moduleImport("wmi").getMember("WMI").getAnInstance().getMember("Win32_Process").getAnInstance().getMember("Create") and qn = "wmi.WMI.Win32_Process.Create" or
  api = API::moduleImport("win32api").getMember("ShellExecute") and qn = "win32api.ShellExecute" or
  api = API::moduleImport("win32com").getMember("shell").getMember("ShellExecuteEx") and qn = "win32com.shell.ShellExecuteEx" or
  api = API::moduleImport("win32com").getMember("shell").getMember("shell").getMember("ShellExecuteEx") and qn = "win32com.shell.shell.ShellExecuteEx" or
  api = API::moduleImport("win32process").getMember("CreateProcess") and qn = "win32process.CreateProcess" or
  api = API::moduleImport("win32process").getMember("CreateProcessAsUser") and qn = "win32process.CreateProcessAsUser"
}
from API::Node api, DataFlow::CallCfgNode n, Call c, Function f,
    BasicBlock bb, string qn, string path, int sl, int sc, int el, int ec
where
  targetApi(api, qn) and
  n = api.getACall() and
  c = n.asExpr() and
  bb = n.asCfgNode().getBasicBlock() and
  bb.hasLocationInfo(path, sl, sc, el, ec) and
  f.getBody().contains(c)
select "path: "+ path,"call function: " + c.getLocation().getStartLine()+":"+c.getLocation().getStartColumn()+
"-"+c.getLocation().getEndLine()+":"+c.getLocation().getEndColumn()
,"call in function: " + f.getName()+"@" +f.getLocation().getStartLine()+"-"+f.getLastStatement().getLocation().getEndLine()
, "callee=" + qn, "basic block: "+sl+":"+sc+"-"+el+":"+ec
        