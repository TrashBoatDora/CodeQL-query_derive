//number of apis 68
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("re").getMember("compile") and qn = "re.compile" or
  api = API::moduleImport("re").getMember("match") and qn = "re.match" or
  api = API::moduleImport("re").getMember("search") and qn = "re.search" or
  api = API::moduleImport("re").getMember("fullmatch") and qn = "re.fullmatch" or
  api = API::moduleImport("re").getMember("findall") and qn = "re.findall" or
  api = API::moduleImport("re").getMember("finditer") and qn = "re.finditer" or
  api = API::moduleImport("re").getMember("sub") and qn = "re.sub" or
  api = API::moduleImport("re").getMember("subn") and qn = "re.subn" or
  api = API::moduleImport("re").getMember("split") and qn = "re.split" or
  api = API::moduleImport("re").getMember("escape") and qn = "re.escape" or
  api = API::moduleImport("re").getMember("Scanner") and qn = "re.Scanner" or
  api = API::moduleImport("re").getMember("Pattern").getMember("match") and qn = "re.Pattern.match" or
  api = API::moduleImport("re").getMember("Pattern").getMember("search") and qn = "re.Pattern.search" or
  api = API::moduleImport("re").getMember("Pattern").getMember("fullmatch") and qn = "re.Pattern.fullmatch" or
  api = API::moduleImport("re").getMember("Pattern").getMember("findall") and qn = "re.Pattern.findall" or
  api = API::moduleImport("re").getMember("Pattern").getMember("finditer") and qn = "re.Pattern.finditer" or
  api = API::moduleImport("re").getMember("Pattern").getMember("sub") and qn = "re.Pattern.sub" or
  api = API::moduleImport("re").getMember("Pattern").getMember("subn") and qn = "re.Pattern.subn" or
  api = API::moduleImport("re").getMember("Pattern").getMember("split") and qn = "re.Pattern.split" or
  api = API::moduleImport("regex").getMember("compile") and qn = "regex.compile" or
  api = API::moduleImport("regex").getMember("match") and qn = "regex.match" or
  api = API::moduleImport("regex").getMember("search") and qn = "regex.search" or
  api = API::moduleImport("regex").getMember("fullmatch") and qn = "regex.fullmatch" or
  api = API::moduleImport("regex").getMember("findall") and qn = "regex.findall" or
  api = API::moduleImport("regex").getMember("finditer") and qn = "regex.finditer" or
  api = API::moduleImport("regex").getMember("sub") and qn = "regex.sub" or
  api = API::moduleImport("regex").getMember("subn") and qn = "regex.subn" or
  api = API::moduleImport("regex").getMember("split") and qn = "regex.split" or
  api = API::moduleImport("regex").getMember("escape") and qn = "regex.escape" or
  api = API::moduleImport("pandas").getMember("Series").getMember("str").getAnInstance().getMember("contains") and qn = "pandas.Series.str.contains" or
  api = API::moduleImport("pandas").getMember("Series").getMember("str").getAnInstance().getMember("match") and qn = "pandas.Series.str.match" or
  api = API::moduleImport("pandas").getMember("Series").getMember("str").getAnInstance().getMember("extract") and qn = "pandas.Series.str.extract" or
  api = API::moduleImport("pandas").getMember("Series").getMember("str").getAnInstance().getMember("extractall") and qn = "pandas.Series.str.extractall" or
  api = API::moduleImport("pandas").getMember("Series").getMember("str").getAnInstance().getMember("replace") and qn = "pandas.Series.str.replace" or
  api = API::moduleImport("pandas").getMember("Series").getMember("str").getAnInstance().getMember("count") and qn = "pandas.Series.str.count" or
  api = API::moduleImport("pandas").getMember("Index").getMember("str").getAnInstance().getMember("contains") and qn = "pandas.Index.str.contains" or
  api = API::moduleImport("pandas").getMember("Index").getMember("str").getAnInstance().getMember("match") and qn = "pandas.Index.str.match" or
  api = API::moduleImport("pandas").getMember("DataFrame").getAnInstance().getMember("filter") and qn = "pandas.DataFrame.filter" or
  api = API::moduleImport("pandas").getMember("DataFrame").getAnInstance().getMember("replace") and qn = "pandas.DataFrame.replace" or
  api = API::moduleImport("pandas").getMember("Series").getAnInstance().getMember("replace") and qn = "pandas.Series.replace" or
  api = API::moduleImport("pyspark").getMember("sql").getMember("functions").getMember("regexp_extract") and qn = "pyspark.sql.functions.regexp_extract" or
  api = API::moduleImport("pyspark").getMember("sql").getMember("functions").getMember("regexp_replace") and qn = "pyspark.sql.functions.regexp_replace" or
  api = API::moduleImport("pyspark").getMember("sql").getMember("Column").getAnInstance().getMember("rlike") and qn = "pyspark.sql.Column.rlike" or
  api = API::moduleImport("django").getMember("urls").getMember("re_path") and qn = "django.urls.re_path" or
  api = API::moduleImport("django").getMember("urls").getMember("path") and qn = "django.urls.path" or
  api = API::moduleImport("django").getMember("core").getMember("validators").getMember("RegexValidator") and qn = "django.core.validators.RegexValidator" or
  api = API::moduleImport("django").getMember("core").getMember("validators").getMember("EmailValidator") and qn = "django.core.validators.EmailValidator" or
  api = API::moduleImport("django").getMember("core").getMember("validators").getMember("URLValidator") and qn = "django.core.validators.URLValidator" or
  api = API::moduleImport("django").getMember("forms").getMember("fields").getMember("RegexField") and qn = "django.forms.fields.RegexField" or
  api = API::moduleImport("wtforms").getMember("validators").getMember("Regexp") and qn = "wtforms.validators.Regexp" or
  api = API::moduleImport("wtforms").getMember("validators").getMember("Email") and qn = "wtforms.validators.Email" or
  api = API::moduleImport("wtforms").getMember("validators").getMember("URL") and qn = "wtforms.validators.URL" or
  api = API::moduleImport("marshmallow").getMember("validate").getMember("Regexp") and qn = "marshmallow.validate.Regexp" or
  api = API::moduleImport("marshmallow").getMember("validate").getMember("Email") and qn = "marshmallow.validate.Email" or
  api = API::moduleImport("marshmallow").getMember("validate").getMember("URL") and qn = "marshmallow.validate.URL" or
  api = API::moduleImport("pydantic").getMember("constr") and qn = "pydantic.constr" or
  api = API::moduleImport("pydantic").getMember("Field") and qn = "pydantic.Field" or
  api = API::moduleImport("fastapi").getMember("Query") and qn = "fastapi.Query" or
  api = API::moduleImport("fastapi").getMember("Path") and qn = "fastapi.Path" or
  api = API::moduleImport("fastapi").getMember("Body") and qn = "fastapi.Body" or
  api = API::moduleImport("parsel").getMember("Selector").getAnInstance().getMember("re") and qn = "parsel.Selector.re" or
  api = API::moduleImport("parsel").getMember("Selector").getAnInstance().getMember("re_first") and qn = "parsel.Selector.re_first" or
  api = API::moduleImport("scrapy").getMember("selector").getMember("Selector").getAnInstance().getMember("re") and qn = "scrapy.selector.Selector.re" or
  api = API::moduleImport("scrapy").getMember("selector").getMember("Selector").getAnInstance().getMember("re_first") and qn = "scrapy.selector.Selector.re_first" or
  api = API::moduleImport("bs4").getMember("BeautifulSoup").getAnInstance().getMember("find_all") and qn = "bs4.BeautifulSoup.find_all" or
  api = API::moduleImport("bs4").getMember("BeautifulSoup").getAnInstance().getMember("find") and qn = "bs4.BeautifulSoup.find" or
  api = API::moduleImport("fnmatch").getMember("fnmatch") and qn = "fnmatch.fnmatch" or
  api = API::moduleImport("fnmatch").getMember("fnmatchcase") and qn = "fnmatch.fnmatchcase" or
  api = API::moduleImport("regex").getMember("Pattern").getAnInstance().getAMember() and qn = "regex.Pattern.*" or
  api = API::moduleImport("regex").getMember("Pattern").getAnInstance().getMember("match") and qn = "regex.Pattern.match" or
  api = API::moduleImport("regex").getMember("Pattern").getAnInstance().getMember("search") and qn = "regex.Pattern.search" or
  api = API::moduleImport("regex").getMember("Pattern").getAnInstance().getMember("fullmatch") and qn = "regex.Pattern.fullmatch" or
  api = API::moduleImport("regex").getMember("Pattern").getAnInstance().getMember("findall") and qn = "regex.Pattern.findall" or
  api = API::moduleImport("regex").getMember("Pattern").getAnInstance().getMember("finditer") and qn = "regex.Pattern.finditer" or
  api = API::moduleImport("regex").getMember("Pattern").getAnInstance().getMember("sub") and qn = "regex.Pattern.sub" or
  api = API::moduleImport("regex").getMember("Pattern").getAnInstance().getMember("split") and qn = "regex.Pattern.split" or
  api = API::moduleImport("re2").getMember("compile") and qn = "re2.compile" or
  api = API::moduleImport("re2").getMember("match") and qn = "re2.match" or
  api = API::moduleImport("re2").getMember("search") and qn = "re2.search" or
  api = API::moduleImport("re2").getMember("fullmatch") and qn = "re2.fullmatch" or
  api = API::moduleImport("re2").getMember("findall") and qn = "re2.findall" or
  api = API::moduleImport("re2").getMember("finditer") and qn = "re2.finditer" or
  api = API::moduleImport("re2").getMember("sub") and qn = "re2.sub" or
  api = API::moduleImport("re2").getMember("split") and qn = "re2.split" or
  api = API::moduleImport("polars").getMember("Expr").getAnInstance().getMember("str").getAnInstance().getMember("contains") and qn = "polars.Expr.str.contains" or
  api = API::moduleImport("polars").getMember("Expr").getAnInstance().getMember("str").getAnInstance().getMember("extract") and qn = "polars.Expr.str.extract" or
  api = API::moduleImport("polars").getMember("Expr").getAnInstance().getMember("str").getAnInstance().getMember("extract_all") and qn = "polars.Expr.str.extract_all" or
  api = API::moduleImport("polars").getMember("Expr").getAnInstance().getMember("str").getAnInstance().getMember("replace") and qn = "polars.Expr.str.replace" or
  api = API::moduleImport("polars").getMember("Expr").getAnInstance().getMember("str").getAnInstance().getMember("replace_all") and qn = "polars.Expr.str.replace_all" or
  api = API::moduleImport("polars").getMember("Expr").getAnInstance().getMember("str").getAnInstance().getMember("count_match") and qn = "polars.Expr.str.count_match" or
  api = API::moduleImport("polars").getMember("Series").getAnInstance().getMember("str").getAnInstance().getMember("contains") and qn = "polars.Series.str.contains" or
  api = API::moduleImport("polars").getMember("Series").getAnInstance().getMember("str").getAnInstance().getMember("extract") and qn = "polars.Series.str.extract" or
  api = API::moduleImport("polars").getMember("Series").getAnInstance().getMember("str").getAnInstance().getMember("extract_all") and qn = "polars.Series.str.extract_all" or
  api = API::moduleImport("polars").getMember("Series").getAnInstance().getMember("str").getAnInstance().getMember("replace") and qn = "polars.Series.str.replace" or
  api = API::moduleImport("polars").getMember("Series").getAnInstance().getMember("str").getAnInstance().getMember("replace_all") and qn = "polars.Series.str.replace_all" or
  api = API::moduleImport("polars").getMember("Series").getAnInstance().getMember("str").getAnInstance().getMember("count_match") and qn = "polars.Series.str.count_match" or
  api = API::builtin("str").getAnInstance().getMember("startswith") and qn = "str.startswith" or
  api = API::builtin("str").getAnInstance().getMember("endswith") and qn = "str.endswith"
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
        