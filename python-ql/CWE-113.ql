//number of apis 85
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("http").getMember("server").getMember("BaseHTTPRequestHandler").getAnInstance().getMember("send_response") and qn = "http.server.BaseHTTPRequestHandler.send_response" or
  api = API::moduleImport("http").getMember("server").getMember("BaseHTTPRequestHandler").getAnInstance().getMember("send_response_only") and qn = "http.server.BaseHTTPRequestHandler.send_response_only" or
  api = API::moduleImport("http").getMember("server").getMember("BaseHTTPRequestHandler").getAnInstance().getMember("send_header") and qn = "http.server.BaseHTTPRequestHandler.send_header" or
  api = API::moduleImport("http").getMember("server").getMember("BaseHTTPRequestHandler").getAnInstance().getMember("send_error") and qn = "http.server.BaseHTTPRequestHandler.send_error" or
  api = API::moduleImport("http").getMember("server").getMember("BaseHTTPRequestHandler").getAnInstance().getMember("end_headers") and qn = "http.server.BaseHTTPRequestHandler.end_headers" or
  api = API::moduleImport("wsgiref").getMember("handlers").getMember("CGIHandler").getAnInstance().getMember("start_response") and qn = "wsgiref.handlers.CGIHandler.start_response" or
  api = API::moduleImport("wsgiref").getMember("handlers").getMember("BaseHandler").getAnInstance().getMember("start_response") and qn = "wsgiref.handlers.BaseHandler.start_response" or
  api = API::moduleImport("wsgiref").getMember("simple_server").getMember("ServerHandler").getAnInstance().getMember("start_response") and qn = "wsgiref.simple_server.ServerHandler.start_response" or
  api = API::moduleImport("wsgiref").getMember("headers").getMember("Headers").getAnInstance().getMember("add_header") and qn = "wsgiref.headers.Headers.add_header" or
  api = API::moduleImport("http").getMember("cookies").getMember("SimpleCookie").getAnInstance().getMember("__setitem__") and qn = "http.cookies.SimpleCookie.__setitem__" or
  api = API::moduleImport("http").getMember("cookies").getMember("SimpleCookie").getAnInstance().getMember("output") and qn = "http.cookies.SimpleCookie.output" or
  api = API::moduleImport("http").getMember("cookies").getMember("Morsel").getAnInstance().getMember("OutputString") and qn = "http.cookies.Morsel.OutputString" or
  api = API::moduleImport("http").getMember("cookies").getMember("Morsel").getAnInstance().getMember("set") and qn = "http.cookies.Morsel.set" or
  api = API::moduleImport("werkzeug").getMember("datastructures").getMember("Headers").getAnInstance().getMember("add") and qn = "werkzeug.datastructures.Headers.add" or
  api = API::moduleImport("werkzeug").getMember("datastructures").getMember("Headers").getAnInstance().getMember("set") and qn = "werkzeug.datastructures.Headers.set" or
  api = API::moduleImport("werkzeug").getMember("datastructures").getMember("Headers").getAnInstance().getMember("add_header") and qn = "werkzeug.datastructures.Headers.add_header" or
  api = API::moduleImport("werkzeug").getMember("utils").getMember("redirect") and qn = "werkzeug.utils.redirect" or
  api = API::moduleImport("flask").getMember("Response").getAnInstance().getMember("set_cookie") and qn = "flask.Response.set_cookie" or
  api = API::moduleImport("flask").getMember("Response").getAnInstance().getMember("delete_cookie") and qn = "flask.Response.delete_cookie" or
  api = API::moduleImport("flask").getMember("redirect") and qn = "flask.redirect" or
  api = API::moduleImport("flask").getMember("make_response") and qn = "flask.make_response" or
  api = API::moduleImport("flask").getMember("send_file") and qn = "flask.send_file" or
  api = API::moduleImport("flask").getMember("url_for") and qn = "flask.url_for" or
  api = API::moduleImport("django").getMember("http").getMember("HttpResponse").getAnInstance().getMember("__setitem__") and qn = "django.http.HttpResponse.__setitem__" or
  api = API::moduleImport("django").getMember("http").getMember("HttpResponse").getAnInstance().getMember("__init__") and qn = "django.http.HttpResponse.__init__" or
  api = API::moduleImport("django").getMember("http").getMember("HttpResponse").getAnInstance().getMember("set_cookie") and qn = "django.http.HttpResponse.set_cookie" or
  api = API::moduleImport("django").getMember("http").getMember("HttpResponse").getAnInstance().getMember("delete_cookie") and qn = "django.http.HttpResponse.delete_cookie" or
  api = API::moduleImport("django").getMember("http").getMember("HttpResponseRedirect").getAnInstance().getMember("__init__") and qn = "django.http.HttpResponseRedirect.__init__" or
  api = API::moduleImport("django").getMember("http").getMember("FileResponse") and qn = "django.http.FileResponse" or
  api = API::moduleImport("django").getMember("shortcuts").getMember("redirect") and qn = "django.shortcuts.redirect" or
  api = API::moduleImport("django").getMember("shortcuts").getMember("resolve_url") and qn = "django.shortcuts.resolve_url" or
  api = API::moduleImport("django").getMember("urls").getMember("reverse") and qn = "django.urls.reverse" or
  api = API::moduleImport("django").getMember("utils").getMember("http").getMember("url_has_allowed_host_and_scheme") and qn = "django.utils.http.url_has_allowed_host_and_scheme" or
  api = API::moduleImport("django").getMember("utils").getMember("text").getMember("get_valid_filename") and qn = "django.utils.text.get_valid_filename" or
  api = API::moduleImport("django").getMember("core").getMember("validators").getMember("validate_slug") and qn = "django.core.validators.validate_slug" or
  api = API::moduleImport("django").getMember("core").getMember("validators").getMember("URLValidator") and qn = "django.core.validators.URLValidator" or
  api = API::moduleImport("starlette").getMember("responses").getMember("Response").getAnInstance().getMember("set_cookie") and qn = "starlette.responses.Response.set_cookie" or
  api = API::moduleImport("starlette").getMember("responses").getMember("Response").getAnInstance().getMember("delete_cookie") and qn = "starlette.responses.Response.delete_cookie" or
  api = API::moduleImport("starlette").getMember("responses").getMember("RedirectResponse").getAnInstance().getMember("__init__") and qn = "starlette.responses.RedirectResponse.__init__" or
  api = API::moduleImport("starlette").getMember("responses").getMember("FileResponse") and qn = "starlette.responses.FileResponse" or
  api = API::moduleImport("starlette").getMember("routing").getMember("Router").getAnInstance().getMember("url_path_for") and qn = "starlette.routing.Router.url_path_for" or
  api = API::moduleImport("starlette").getMember("datastructures").getMember("MutableHeaders").getAnInstance().getMember("append") and qn = "starlette.datastructures.MutableHeaders.append" or
  api = API::moduleImport("fastapi").getMember("param_functions").getMember("Path") and qn = "fastapi.param_functions.Path" or
  api = API::moduleImport("fastapi").getMember("param_functions").getMember("Query") and qn = "fastapi.param_functions.Query" or
  api = API::moduleImport("fastapi").getMember("Response").getAnInstance().getMember("set_cookie") and qn = "fastapi.Response.set_cookie" or
  api = API::moduleImport("fastapi").getMember("responses").getMember("RedirectResponse").getAnInstance().getMember("__init__") and qn = "fastapi.responses.RedirectResponse.__init__" or
  api = API::moduleImport("aiohttp").getMember("web").getMember("Response").getAnInstance().getMember("set_cookie") and qn = "aiohttp.web.Response.set_cookie" or
  api = API::moduleImport("aiohttp").getMember("web").getMember("Response").getAnInstance().getMember("del_cookie") and qn = "aiohttp.web.Response.del_cookie" or
  api = API::moduleImport("aiohttp").getMember("web").getMember("HTTPFound").getAnInstance().getMember("__init__") and qn = "aiohttp.web.HTTPFound.__init__" or
  api = API::moduleImport("aiohttp").getMember("web").getMember("HTTPMovedPermanently").getAnInstance().getMember("__init__") and qn = "aiohttp.web.HTTPMovedPermanently.__init__" or
  api = API::moduleImport("aiohttp").getMember("web").getMember("FileResponse") and qn = "aiohttp.web.FileResponse" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("set_header") and qn = "tornado.web.RequestHandler.set_header" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("add_header") and qn = "tornado.web.RequestHandler.add_header" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("set_cookie") and qn = "tornado.web.RequestHandler.set_cookie" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("clear_cookie") and qn = "tornado.web.RequestHandler.clear_cookie" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("clear_all_cookies") and qn = "tornado.web.RequestHandler.clear_all_cookies" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("clear_header") and qn = "tornado.web.RequestHandler.clear_header" or
  api = API::moduleImport("tornado").getMember("web").getMember("RequestHandler").getAnInstance().getMember("redirect") and qn = "tornado.web.RequestHandler.redirect" or
  api = API::moduleImport("tornado").getMember("routing").getMember("URLSpec") and qn = "tornado.routing.URLSpec" or
  api = API::moduleImport("bottle").getMember("response").getMember("set_header") and qn = "bottle.response.set_header" or
  api = API::moduleImport("bottle").getMember("response").getMember("set_cookie") and qn = "bottle.response.set_cookie" or
  api = API::moduleImport("bottle").getMember("response").getMember("delete_cookie") and qn = "bottle.response.delete_cookie" or
  api = API::moduleImport("bottle").getMember("redirect") and qn = "bottle.redirect" or
  api = API::moduleImport("bottle").getMember("url") and qn = "bottle.url" or
  api = API::moduleImport("pyramid").getMember("response").getMember("Response").getAnInstance().getMember("set_cookie") and qn = "pyramid.response.Response.set_cookie" or
  api = API::moduleImport("pyramid").getMember("response").getMember("Response").getAnInstance().getMember("delete_cookie") and qn = "pyramid.response.Response.delete_cookie" or
  api = API::moduleImport("falcon").getMember("Response").getAnInstance().getMember("set_header") and qn = "falcon.Response.set_header" or
  api = API::moduleImport("falcon").getMember("Response").getAnInstance().getMember("append_header") and qn = "falcon.Response.append_header" or
  api = API::moduleImport("falcon").getMember("Response").getAnInstance().getMember("set_headers") and qn = "falcon.Response.set_headers" or
  api = API::moduleImport("falcon").getMember("Response").getAnInstance().getMember("set_cookie") and qn = "falcon.Response.set_cookie" or
  api = API::moduleImport("falcon").getMember("Response").getAnInstance().getMember("unset_cookie") and qn = "falcon.Response.unset_cookie" or
  api = API::moduleImport("twisted").getMember("web").getMember("http").getMember("Request").getAnInstance().getMember("setHeader") and qn = "twisted.web.http.Request.setHeader" or
  api = API::moduleImport("twisted").getMember("web").getMember("http").getMember("Request").getAnInstance().getMember("redirect") and qn = "twisted.web.http.Request.redirect" or
  api = API::moduleImport("twisted").getMember("web").getMember("http_headers").getMember("Headers").getAnInstance().getMember("addRawHeader") and qn = "twisted.web.http_headers.Headers.addRawHeader" or
  api = API::moduleImport("twisted").getMember("web").getMember("http_headers").getMember("Headers").getAnInstance().getMember("setRawHeaders") and qn = "twisted.web.http_headers.Headers.setRawHeaders" or
  api = API::moduleImport("quart").getMember("Response").getAnInstance().getMember("set_cookie") and qn = "quart.Response.set_cookie" or
  api = API::moduleImport("quart").getMember("Response").getAnInstance().getMember("delete_cookie") and qn = "quart.Response.delete_cookie" or
  api = API::moduleImport("quart").getMember("redirect") and qn = "quart.redirect" or
  api = API::moduleImport("quart").getMember("make_response") and qn = "quart.make_response" or
  api = API::moduleImport("werkzeug").getMember("wrappers").getMember("Response").getAnInstance().getMember("set_cookie") and qn = "werkzeug.wrappers.Response.set_cookie" or
  api = API::moduleImport("werkzeug").getMember("wrappers").getMember("Response").getAnInstance().getMember("delete_cookie") and qn = "werkzeug.wrappers.Response.delete_cookie" or
  api = API::moduleImport("werkzeug").getMember("utils").getMember("secure_filename") and qn = "werkzeug.utils.secure_filename" or
  api = API::moduleImport("urllib").getMember("parse").getMember("urlparse") and qn = "urllib.parse.urlparse" or
  api = API::moduleImport("mimetypes").getMember("guess_type") and qn = "mimetypes.guess_type" or
  api = API::moduleImport("sanic").getMember("response").getMember("redirect") and qn = "sanic.response.redirect" or
  api = API::moduleImport("werkzeug").getMember("wrappers").getMember("response").getMember("Response").getMember("headers").getMember("__setitem__") and qn = "werkzeug.wrappers.response.Response.headers.__setitem__" or
  api = API::moduleImport("werkzeug").getMember("wrappers").getMember("Response").getMember("headers").getMember("add") and qn = "werkzeug.wrappers.Response.headers.add" or
  api = API::moduleImport("flask").getMember("Response").getMember("headers").getMember("__setitem__") and qn = "flask.Response.headers.__setitem__" or
  api = API::moduleImport("flask").getMember("Response").getMember("headers").getMember("add") and qn = "flask.Response.headers.add" or 
  api = API::moduleImport("starlette").getMember("responses").getMember("Response").getMember("headers").getMember("__setitem__") and qn = "starlette.responses.Response.headers.__setitem__" or
  api = API::moduleImport("fastapi").getMember("Response").getMember("headers").getMember("__setitem__") and qn = "fastapi.Response.headers.__setitem__" or
  api = API::moduleImport("aiohttp").getMember("web").getMember("Response").getMember("headers").getMember("__setitem__") and qn = "aiohttp.web.Response.headers.__setitem__" or
  api = API::moduleImport("pyramid").getMember("response").getMember("Response").getMember("headers").getMember("__setitem__") and qn = "pyramid.response.Response.headers.__setitem__" or
  api = API::moduleImport("quart").getMember("Response").getMember("headers").getMember("__setitem__") and qn = "quart.Response.headers.__setitem__" or
  api = API::moduleImport("werkzeug").getMember("urls").getMember("url_parse") and qn = "werkzeug.urls.url_parse" or
  api = API::moduleImport("sanic").getMember("response").getMember("Response").getMember("cookies").getMember("__setitem__") and qn = "sanic.response.Response.cookies.__setitem__" or
  api = API::moduleImport("werkzeug").getMember("wrappers").getMember("response").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("__setitem__") and qn = "werkzeug.wrappers.response.Response.headers.__setitem__" or
  api = API::moduleImport("werkzeug").getMember("wrappers").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("add") and qn = "werkzeug.wrappers.Response.headers.add" or
  api = API::moduleImport("flask").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("__setitem__") and qn = "flask.Response.headers.__setitem__" or
  api = API::moduleImport("flask").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("add") and qn = "flask.Response.headers.add" or
  api = API::moduleImport("starlette").getMember("responses").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("__setitem__") and qn = "starlette.responses.Response.headers.__setitem__" or
  api = API::moduleImport("fastapi").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("__setitem__") and qn = "fastapi.Response.headers.__setitem__" or
  api = API::moduleImport("aiohttp").getMember("web").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("__setitem__") and qn = "aiohttp.web.Response.headers.__setitem__" or
  api = API::moduleImport("pyramid").getMember("response").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("__setitem__") and qn = "pyramid.response.Response.headers.__setitem__" or
  api = API::moduleImport("quart").getMember("Response").getAnInstance().getMember("headers").getAnInstance().getMember("__setitem__") and qn = "quart.Response.headers.__setitem__" or
  api = API::moduleImport("werkzeug").getMember("urls").getMember("url_parse") and qn = "werkzeug.urls.url_parse" or
  api = API::moduleImport("sanic").getMember("response").getMember("Response").getAnInstance().getMember("cookies").getAnInstance().getMember("__setitem__") and qn = "sanic.response.Response.cookies.__setitem__"
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
        