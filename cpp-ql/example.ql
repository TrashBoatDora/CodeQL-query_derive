import cpp

from Function f, FunctionCall fc, Stmt s
where
  // 找呼叫 "open" 的 function call
  fc.getTarget().getName() = "sort" and
  f = fc.getEnclosingFunction() and
  s.getEnclosingFunction() = f and
  not exists(Stmt s2 |
    s2.getEnclosingFunction() = f and
    s2.getLocation().getEndLine() > s.getLocation().getEndLine()
  )
select
  f.getFile().getRelativePath(),
  f.getName(),
  f.getLocation().getStartLine(),
  s.getLocation().getEndLine()

