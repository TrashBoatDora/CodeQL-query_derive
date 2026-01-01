//number of apis 19
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("tempfile").getMember("mktemp") and qn = "tempfile.mktemp" or
  api = API::builtin("open") and qn = "open" or
  api = API::moduleImport("os").getMember("open") and qn = "os.open" or
  api = API::moduleImport("pathlib").getMember("Path").getAnInstance().getMember("open") and qn = "pathlib.Path.open" or
  api = API::moduleImport("pathlib").getMember("Path").getAnInstance().getMember("touch") and qn = "pathlib.Path.touch" or
  api = API::moduleImport("pathlib").getMember("Path").getAnInstance().getMember("write_text") and qn = "pathlib.Path.write_text" or
  api = API::moduleImport("pathlib").getMember("Path").getAnInstance().getMember("write_bytes") and qn = "pathlib.Path.write_bytes" or
  api = API::moduleImport("tempfile").getMember("NamedTemporaryFile") and qn = "tempfile.NamedTemporaryFile" or
  api = API::moduleImport("tempfile").getMember("TemporaryFile") and qn = "tempfile.TemporaryFile" or
  api = API::moduleImport("tempfile").getMember("SpooledTemporaryFile") and qn = "tempfile.SpooledTemporaryFile" or
  api = API::moduleImport("tempfile").getMember("TemporaryDirectory") and qn = "tempfile.TemporaryDirectory" or
  api = API::moduleImport("tempfile").getMember("mkstemp") and qn = "tempfile.mkstemp" or
  api = API::moduleImport("tempfile").getMember("mkdtemp") and qn = "tempfile.mkdtemp" or
  api = API::moduleImport("tempfile").getMember("gettempdir") and qn = "tempfile.gettempdir" or
  api = API::moduleImport("tempfile").getMember("gettempprefix") and qn = "tempfile.gettempprefix" or
  api = API::moduleImport("tempfile").getMember("gettempprefixb") and qn = "tempfile.gettempprefixb" or
  api = API::moduleImport("aiofiles").getMember("tempfile").getMember("NamedTemporaryFile") and qn = "aiofiles.tempfile.NamedTemporaryFile" or
  api = API::moduleImport("aiofiles").getMember("tempfile").getMember("TemporaryDirectory") and qn = "aiofiles.tempfile.TemporaryDirectory" or
  api = API::moduleImport("django").getMember("core").getMember("files").getMember("temp").getMember("NamedTemporaryFile") and qn = "django.core.files.temp.NamedTemporaryFile" or
  api = API::moduleImport("os").getMember("tmpnam") and qn = "os.tmpnam" or
  api = API::moduleImport("os").getMember("tempnam") and qn = "os.tempnam" or
  api = API::moduleImport("django").getMember("core").getMember("files").getMember("temp").getMember("TemporaryFile") and qn = "django.core.files.temp.TemporaryFile"
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
        