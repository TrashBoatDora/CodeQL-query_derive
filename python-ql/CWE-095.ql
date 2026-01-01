//number of apis 29
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::builtin("eval") and qn = "eval" or
  api = API::builtin("exec") and qn = "exec" or
  api = API::builtin("compile") and qn = "compile" or
  api = API::moduleImport("code").getMember("InteractiveInterpreter").getAnInstance().getMember("runsource") and qn = "code.InteractiveInterpreter.runsource" or
  api = API::moduleImport("code").getMember("InteractiveInterpreter").getAnInstance().getMember("runcode") and qn = "code.InteractiveInterpreter.runcode" or
  api = API::moduleImport("code").getMember("InteractiveConsole").getAnInstance().getMember("push") and qn = "code.InteractiveConsole.push" or
  api = API::moduleImport("codeop").getMember("compile_command") and qn = "codeop.compile_command" or
  api = API::moduleImport("pandas").getMember("eval") and qn = "pandas.eval" or
  api = API::moduleImport("pandas").getMember("DataFrame").getAnInstance().getMember("eval") and qn = "pandas.DataFrame.eval" or
  api = API::moduleImport("pandas").getMember("DataFrame").getAnInstance().getMember("query") and qn = "pandas.DataFrame.query" or
  api = API::moduleImport("numexpr").getMember("evaluate") and qn = "numexpr.evaluate" or
  api = API::moduleImport("sympy").getMember("sympify") and qn = "sympy.sympify" or
  api = API::moduleImport("sympy").getMember("parsing").getMember("sympy_parser").getMember("parse_expr") and qn = "sympy.parsing.sympy_parser.parse_expr" or
  api = API::moduleImport("asteval").getMember("Interpreter") and qn = "asteval.Interpreter" or
  api = API::moduleImport("asteval").getMember("Interpreter").getAnInstance().getMember("eval") and qn = "asteval.Interpreter.eval" or
  api = API::moduleImport("simpleeval").getMember("SimpleEval") and qn = "simpleeval.SimpleEval" or
  api = API::builtin("input") and qn = "input" or
  api = API::moduleImport("ast").getMember("literal_eval") and qn = "ast.literal_eval" or
  api = API::moduleImport("runpy").getMember("run_module") and qn = "runpy.run_module" or
  api = API::moduleImport("runpy").getMember("run_path") and qn = "runpy.run_path" or
  api = API::moduleImport("modin").getMember("pandas").getMember("eval") and qn = "modin.pandas.eval" or
  api = API::moduleImport("modin").getMember("pandas").getMember("DataFrame").getAnInstance().getMember("eval") and qn = "modin.pandas.DataFrame.eval" or
  api = API::moduleImport("modin").getMember("pandas").getMember("DataFrame").getAnInstance().getMember("query") and qn = "modin.pandas.DataFrame.query" or
  api = API::moduleImport("sympy").getMember("lambdify") and qn = "sympy.lambdify" or
  api = API::moduleImport("simpleeval").getMember("EvalWithCompoundTypes") and qn = "simpleeval.EvalWithCompoundTypes" or
  api = API::moduleImport("json").getMember("loads") and qn = "json.loads" or
  api = API::moduleImport("yaml").getMember("safe_load") and qn = "yaml.safe_load" or
  api = API::moduleImport("tomllib").getMember("loads") and qn = "tomllib.loads" or
  api = API::moduleImport("RestrictedPython").getMember("compile_restricted") and qn = "RestrictedPython.compile_restricted" or
  api = API::moduleImport("dask").getMember("dataframe").getMember("DataFrame").getAnInstance().getMember("eval") and qn = "dask.dataframe.DataFrame.eval" or
  api = API::moduleImport("dask").getMember("dataframe").getMember("DataFrame").getAnInstance().getMember("query") and qn = "dask.dataframe.DataFrame.query" or
  api = API::builtin("execfile") and qn = "execfile" or
  api = API::moduleImport("asteval") and qn = "asteval" or
  api = API::moduleImport("simpleeval") and qn = "simpleeval"
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
        