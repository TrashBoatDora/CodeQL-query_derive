import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow

predicate targetApi(API::Node api, string qn) {
  api = API::builtin("open") and qn = "open" or
  api = API::moduleImport("os").getMember("open")     and qn = "os.open"     or
  api = API::moduleImport("os").getMember("readlink") and qn = "os.readlink" or
  api = API::moduleImport("os").getMember("symlink")  and qn = "os.symlink"  or
  api = API::moduleImport("os").getMember("link")     and qn = "os.link"     or
  api = API::moduleImport("os").getMember("remove")   and qn = "os.remove"   or
  api = API::moduleImport("os").getMember("unlink")   and qn = "os.unlink"   or
  api = API::moduleImport("os").getMember("path").getMember("join") and qn = "os.path.join" or
  api = API::moduleImport("pathlib").getMember("Path").getAnInstance().getMember("iterdir")
        and qn = "pathlib.Path.iterdir"
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
