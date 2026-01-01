/**
 * @name 列出所有 Python 函式 (problem)
 * @kind problem
 * @id demo.py.list-funcs
 * @problem.severity warning
 */
import python

from Function f
select f, "Function: " + f.getName()