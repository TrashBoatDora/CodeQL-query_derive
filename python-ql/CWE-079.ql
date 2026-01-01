//number of apis 67
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("flask").getMember("render_template") and qn = "flask.render_template" or
  api = API::moduleImport("flask").getMember("render_template_string") and qn = "flask.render_template_string" or
  api = API::moduleImport("flask").getMember("make_response") and qn = "flask.make_response" or
  api = API::moduleImport("flask").getMember("Response") and qn = "flask.Response" or
  api = API::moduleImport("django").getMember("http").getMember("HttpResponse") and qn = "django.http.HttpResponse" or
  api = API::moduleImport("django").getMember("http").getMember("JsonResponse") and qn = "django.http.JsonResponse" or
  api = API::moduleImport("django").getMember("template").getMember("response").getMember("TemplateResponse") and qn = "django.template.response.TemplateResponse" or
  api = API::moduleImport("django").getMember("shortcuts").getMember("render") and qn = "django.shortcuts.render" or
  api = API::moduleImport("django").getMember("template").getMember("loader").getMember("render_to_string") and qn = "django.template.loader.render_to_string" or
  api = API::moduleImport("django").getMember("template").getMember("Template").getAnInstance().getMember("render") and qn = "django.template.Template.render" or
  api = API::moduleImport("django").getMember("utils").getMember("safestring").getMember("mark_safe") and qn = "django.utils.safestring.mark_safe" or
  api = API::moduleImport("django").getMember("utils").getMember("safestring").getMember("SafeString") and qn = "django.utils.safestring.SafeString" or
  api = API::moduleImport("django").getMember("utils").getMember("html").getMember("escape") and qn = "django.utils.html.escape" or
  api = API::moduleImport("django").getMember("utils").getMember("html").getMember("escapejs") and qn = "django.utils.html.escapejs" or
  api = API::moduleImport("django").getMember("utils").getMember("html").getMember("conditional_escape") and qn = "django.utils.html.conditional_escape" or
  api = API::moduleImport("django").getMember("utils").getMember("html").getMember("format_html") and qn = "django.utils.html.format_html" or
  api = API::moduleImport("django").getMember("utils").getMember("html").getMember("format_html_join") and qn = "django.utils.html.format_html_join" or
  api = API::moduleImport("django").getMember("template").getMember("defaultfilters").getMember("escape") and qn = "django.template.defaultfilters.escape" or
  api = API::moduleImport("django").getMember("template").getMember("defaultfilters").getMember("safe") and qn = "django.template.defaultfilters.safe" or
  api = API::moduleImport("jinja2").getMember("Template").getAnInstance().getMember("render") and qn = "jinja2.Template.render" or
  api = API::moduleImport("jinja2").getMember("Environment") and qn = "jinja2.Environment" or
  api = API::moduleImport("jinja2").getMember("select_autoescape") and qn = "jinja2.select_autoescape" or
  api = API::moduleImport("jinja2").getMember("filters").getMember("do_mark_safe") and qn = "jinja2.filters.do_mark_safe" or
  api = API::moduleImport("markupsafe").getMember("Markup") and qn = "markupsafe.Markup" or
  api = API::moduleImport("markupsafe").getMember("escape") and qn = "markupsafe.escape" or
  api = API::moduleImport("markupsafe").getMember("escape_silent") and qn = "markupsafe.escape_silent" or
  api = API::moduleImport("mako").getMember("template").getMember("Template").getAnInstance().getMember("render") and qn = "mako.template.Template.render" or
  api = API::moduleImport("mako").getMember("filters").getMember("html_escape") and qn = "mako.filters.html_escape" or
  api = API::moduleImport("mako").getMember("filters").getMember("url_escape") and qn = "mako.filters.url_escape" or
  api = API::moduleImport("chameleon").getMember("PageTemplate").getAnInstance().getMember("render") and qn = "chameleon.PageTemplate.render" or
  api = API::moduleImport("chameleon").getMember("PageTemplateFile").getAnInstance().getMember("render") and qn = "chameleon.PageTemplateFile.render" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("render") and qn = "tornado.web.RequestHandler.render" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("render_string") and qn = "tornado.web.RequestHandler.render_string" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("write") and qn = "tornado.web.RequestHandler.write" or
  api = API::moduleImport("tornado").getMember("template").getMember("Template").getAnInstance().getMember("generate") and qn = "tornado.template.Template.generate" or
  api = API::moduleImport("tornado").getMember("escape").getMember("xhtml_escape") and qn = "tornado.escape.xhtml_escape" or
  api = API::moduleImport("tornado").getMember("escape").getMember("xhtml_unescape") and qn = "tornado.escape.xhtml_unescape" or
  api = API::moduleImport("tornado").getMember("escape").getMember("linkify") and qn = "tornado.escape.linkify" or
  api = API::moduleImport("starlette").getMember("templating").getMember("Jinja2Templates").getAnInstance().getMember("TemplateResponse") and qn = "starlette.templating.Jinja2Templates.TemplateResponse" or
  api = API::moduleImport("starlette").getMember("responses").getMember("HTMLResponse") and qn = "starlette.responses.HTMLResponse" or
  api = API::moduleImport("fastapi").getMember("templating").getMember("Jinja2Templates").getAnInstance().getMember("TemplateResponse") and qn = "fastapi.templating.Jinja2Templates.TemplateResponse" or
  api = API::moduleImport("fastapi").getMember("responses").getMember("HTMLResponse") and qn = "fastapi.responses.HTMLResponse" or
  api = API::moduleImport("aiohttp_jinja2").getMember("template") and qn = "aiohttp_jinja2.template" or
  api = API::moduleImport("aiohttp_jinja2").getMember("render_template") and qn = "aiohttp_jinja2.render_template" or
  api = API::moduleImport("aiohttp").getMember("web").getMember("Response") and qn = "aiohttp.web.Response" or
  api = API::moduleImport("bottle").getMember("template") and qn = "bottle.template" or
  api = API::moduleImport("bottle").getMember("SimpleTemplate") and qn = "bottle.SimpleTemplate" or
  api = API::moduleImport("bottle").getMember("SimpleTemplate").getAnInstance().getMember("render") and qn = "bottle.SimpleTemplate.render" or
  api = API::moduleImport("pyramid").getMember("renderers").getMember("render") and qn = "pyramid.renderers.render" or
  api = API::moduleImport("pyramid").getMember("renderers").getMember("render_to_response") and qn = "pyramid.renderers.render_to_response" or
  api = API::moduleImport("pyramid").getMember("response").getMember("Response") and qn = "pyramid.response.Response" or
  api = API::moduleImport("werkzeug").getMember("utils").getMember("escape") and qn = "werkzeug.utils.escape" or
  api = API::moduleImport("werkzeug").getMember("wrappers").getMember("Response") and qn = "werkzeug.wrappers.Response" or
  api = API::moduleImport("genshi").getMember("core").getMember("Markup") and qn = "genshi.core.Markup" or
  api = API::moduleImport("genshi").getMember("filters").getMember("HTMLSanitizer") and qn = "genshi.filters.HTMLSanitizer" or
  api = API::moduleImport("genshi").getMember("input").getMember("HTML") and qn = "genshi.input.HTML" or
  api = API::moduleImport("genshi").getMember("input").getMember("XML") and qn = "genshi.input.XML" or
  api = API::moduleImport("bleach").getMember("clean") and qn = "bleach.clean" or
  api = API::moduleImport("bleach").getMember("linkifier").getMember("Linker").getAnInstance().getMember("linkify") and qn = "bleach.linkifier.Linker.linkify" or
  api = API::moduleImport("html").getMember("escape") and qn = "html.escape" or
  api = API::moduleImport("html").getMember("unescape") and qn = "html.unescape" or
  api = API::moduleImport("xml").getMember("sax").getMember("saxutils").getMember("escape") and qn = "xml.sax.saxutils.escape" or
  api = API::moduleImport("xml").getMember("sax").getMember("saxutils").getMember("unescape") and qn = "xml.sax.saxutils.unescape" or
  api = API::moduleImport("quart").getMember("render_template") and qn = "quart.render_template" or
  api = API::moduleImport("quart").getMember("render_template_string") and qn = "quart.render_template_string" or
  api = API::moduleImport("quart").getMember("Response") and qn = "quart.Response" or
  api = API::moduleImport("sanic").getMember("response").getMember("html") and qn = "sanic.response.html" or
  api = API::moduleImport("sanic_jinja2").getMember("render") and qn = "sanic_jinja2.render" or
  api = API::moduleImport("flask").getMember("Markup") and qn = "flask.Markup" or
  api = API::moduleImport("flask").getMember("escape") and qn = "flask.escape" or
  api = API::moduleImport("jinja2").getMember("Environment").getAnInstance().getMember("get_template") and qn = "jinja2.Environment.get_template" or
  api = API::moduleImport("jinja2").getMember("escape") and qn = "jinja2.escape" or
  api = API::moduleImport("jinja2").getMember("Markup") and qn = "jinja2.Markup" or
  api = API::moduleImport("jinja2").getMember("filters").getMember("do_escape") and qn = "jinja2.filters.do_escape" or
  api = API::moduleImport("mako").getMember("lookup").getMember("TemplateLookup").getAnInstance().getMember("get_template") and qn = "mako.lookup.TemplateLookup.get_template" or
  api = API::moduleImport("genshi").getMember("template").getMember("TemplateLoader").getAnInstance().getMember("load") and qn = "genshi.template.TemplateLoader.load" or
  api = API::moduleImport("genshi").getMember("template").getMember("base").getMember("Template").getAnInstance().getMember("generate") and qn = "genshi.template.base.Template.generate" or
  api = API::moduleImport("sanic_jinja2").getMember("render") and qn = "sanic_jinja2.render"
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
        