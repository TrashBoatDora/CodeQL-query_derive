//number of apis 104
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("requests").getMember("get") and qn = "requests.get" or
  api = API::moduleImport("requests").getMember("post") and qn = "requests.post" or
  api = API::moduleImport("requests").getMember("put") and qn = "requests.put" or
  api = API::moduleImport("requests").getMember("delete") and qn = "requests.delete" or
  api = API::moduleImport("requests").getMember("head") and qn = "requests.head" or
  api = API::moduleImport("requests").getMember("options") and qn = "requests.options" or
  api = API::moduleImport("requests").getMember("patch") and qn = "requests.patch" or
  api = API::moduleImport("requests").getMember("request") and qn = "requests.request" or
  api = API::moduleImport("requests").getMember("Session") and qn = "requests.Session" or
  api = API::moduleImport("requests").getMember("Session").getAnInstance().getMember("get") and qn = "requests.Session.get" or
  api = API::moduleImport("requests").getMember("Session").getAnInstance().getMember("post") and qn = "requests.Session.post" or
  api = API::moduleImport("requests").getMember("Session").getAnInstance().getMember("put") and qn = "requests.Session.put" or
  api = API::moduleImport("requests").getMember("Session").getAnInstance().getMember("delete") and qn = "requests.Session.delete" or
  api = API::moduleImport("requests").getMember("Session").getAnInstance().getMember("head") and qn = "requests.Session.head" or
  api = API::moduleImport("requests").getMember("Session").getAnInstance().getMember("options") and qn = "requests.Session.options" or
  api = API::moduleImport("requests").getMember("Session").getAnInstance().getMember("patch") and qn = "requests.Session.patch" or
  api = API::moduleImport("requests").getMember("Session").getAnInstance().getMember("request") and qn = "requests.Session.request" or
  api = API::moduleImport("requests").getMember("adapters").getMember("HTTPAdapter").getAnInstance().getMember("send") and qn = "requests.adapters.HTTPAdapter.send" or
  api = API::moduleImport("requests_futures").getMember("sessions").getMember("FuturesSession").getAnInstance().getMember("get") and qn = "requests_futures.sessions.FuturesSession.get" or
  api = API::moduleImport("requests_futures").getMember("sessions").getMember("FuturesSession").getAnInstance().getMember("post") and qn = "requests_futures.sessions.FuturesSession.post" or
  api = API::moduleImport("grequests").getMember("get") and qn = "grequests.get" or
  api = API::moduleImport("grequests").getMember("post") and qn = "grequests.post" or
  api = API::moduleImport("grequests").getMember("map") and qn = "grequests.map" or
  api = API::moduleImport("urllib").getMember("request").getMember("urlopen") and qn = "urllib.request.urlopen" or
  api = API::moduleImport("urllib").getMember("request").getMember("urlretrieve") and qn = "urllib.request.urlretrieve" or
  api = API::moduleImport("urllib").getMember("request").getMember("Request") and qn = "urllib.request.Request" or
  api = API::moduleImport("urllib").getMember("request").getMember("OpenerDirector").getAnInstance().getMember("open") and qn = "urllib.request.OpenerDirector.open" or
  api = API::moduleImport("urllib3").getMember("PoolManager").getAnInstance().getMember("request") and qn = "urllib3.PoolManager.request" or
  api = API::moduleImport("urllib3").getMember("ProxyManager").getAnInstance().getMember("request") and qn = "urllib3.ProxyManager.request" or
  api = API::moduleImport("urllib3").getMember("connectionpool").getMember("HTTPConnectionPool").getAnInstance().getMember("urlopen") and qn = "urllib3.connectionpool.HTTPConnectionPool.urlopen" or
  api = API::moduleImport("urllib3").getMember("request") and qn = "urllib3.request" or
  api = API::moduleImport("httpx").getMember("get") and qn = "httpx.get" or
  api = API::moduleImport("httpx").getMember("post") and qn = "httpx.post" or
  api = API::moduleImport("httpx").getMember("put") and qn = "httpx.put" or
  api = API::moduleImport("httpx").getMember("delete") and qn = "httpx.delete" or
  api = API::moduleImport("httpx").getMember("head") and qn = "httpx.head" or
  api = API::moduleImport("httpx").getMember("options") and qn = "httpx.options" or
  api = API::moduleImport("httpx").getMember("patch") and qn = "httpx.patch" or
  api = API::moduleImport("httpx").getMember("stream") and qn = "httpx.stream" or
  api = API::moduleImport("httpx").getMember("request") and qn = "httpx.request" or
  api = API::moduleImport("httpx").getMember("Client") and qn = "httpx.Client" or
  api = API::moduleImport("httpx").getMember("Client").getAnInstance().getMember("request") and qn = "httpx.Client.request" or
  api = API::moduleImport("httpx").getMember("AsyncClient") and qn = "httpx.AsyncClient" or
  api = API::moduleImport("httpx").getMember("AsyncClient").getAnInstance().getMember("request") and qn = "httpx.AsyncClient.request" or
  api = API::moduleImport("httpx").getMember("AsyncClient").getAnInstance().getMember("stream") and qn = "httpx.AsyncClient.stream" or
  api = API::moduleImport("aiohttp").getMember("request") and qn = "aiohttp.request" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("get") and qn = "aiohttp.ClientSession.get" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("post") and qn = "aiohttp.ClientSession.post" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("put") and qn = "aiohttp.ClientSession.put" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("delete") and qn = "aiohttp.ClientSession.delete" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("head") and qn = "aiohttp.ClientSession.head" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("options") and qn = "aiohttp.ClientSession.options" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("patch") and qn = "aiohttp.ClientSession.patch" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("request") and qn = "aiohttp.ClientSession.request" or
  api = API::moduleImport("aiohttp").getMember("ClientSession").getAnInstance().getMember("ws_connect") and qn = "aiohttp.ClientSession.ws_connect" or
  api = API::moduleImport("aiohttp").getMember("TCPConnector") and qn = "aiohttp.TCPConnector" or
  api = API::moduleImport("aiohttp").getMember("ClientTimeout") and qn = "aiohttp.ClientTimeout" or
  api = API::moduleImport("tornado").getMember("httpclient").getMember("HTTPClient").getAnInstance().getMember("fetch") and qn = "tornado.httpclient.HTTPClient.fetch" or
  api = API::moduleImport("tornado").getMember("httpclient").getMember("AsyncHTTPClient").getAnInstance().getMember("fetch") and qn = "tornado.httpclient.AsyncHTTPClient.fetch" or
  api = API::moduleImport("tornado").getMember("simple_httpclient").getMember("SimpleAsyncHTTPClient").getAnInstance().getMember("fetch") and qn = "tornado.simple_httpclient.SimpleAsyncHTTPClient.fetch" or
  api = API::moduleImport("twisted").getMember("web").getMember("client").getMember("Agent").getAnInstance().getMember("request") and qn = "twisted.web.client.Agent.request" or
  api = API::moduleImport("treq").getMember("get") and qn = "treq.get" or
  api = API::moduleImport("treq").getMember("post") and qn = "treq.post" or
  api = API::moduleImport("treq").getMember("request") and qn = "treq.request" or
  api = API::moduleImport("http").getMember("client").getMember("HTTPConnection").getAnInstance().getMember("request") and qn = "http.client.HTTPConnection.request" or
  api = API::moduleImport("http").getMember("client").getMember("HTTPSConnection").getAnInstance().getMember("request") and qn = "http.client.HTTPSConnection.request" or
  api = API::moduleImport("http").getMember("client").getMember("HTTPConnection").getAnInstance().getMember("putrequest") and qn = "http.client.HTTPConnection.putrequest" or
  api = API::moduleImport("http").getMember("client").getMember("HTTPConnection").getAnInstance().getMember("putheader") and qn = "http.client.HTTPConnection.putheader" or
  api = API::moduleImport("http").getMember("client").getMember("HTTPConnection").getAnInstance().getMember("endheaders") and qn = "http.client.HTTPConnection.endheaders" or
  api = API::moduleImport("urllib").getMember("parse").getMember("urlparse") and qn = "urllib.parse.urlparse" or
  api = API::moduleImport("urllib").getMember("parse").getMember("urlsplit") and qn = "urllib.parse.urlsplit" or
  api = API::moduleImport("urllib").getMember("parse").getMember("urljoin") and qn = "urllib.parse.urljoin" or
  api = API::moduleImport("socket").getMember("create_connection") and qn = "socket.create_connection" or
  api = API::moduleImport("socket").getMember("socket").getAnInstance().getMember("connect") and qn = "socket.socket.connect" or
  api = API::moduleImport("socket").getMember("getaddrinfo") and qn = "socket.getaddrinfo" or
  api = API::moduleImport("ftplib").getMember("FTP").getAnInstance().getMember("connect") and qn = "ftplib.FTP.connect" or
  api = API::moduleImport("ftplib").getMember("FTP").getAnInstance().getMember("login") and qn = "ftplib.FTP.login" or
  api = API::moduleImport("ftplib").getMember("FTP").getAnInstance().getMember("retrbinary") and qn = "ftplib.FTP.retrbinary" or
  api = API::moduleImport("ftplib").getMember("FTP").getAnInstance().getMember("storbinary") and qn = "ftplib.FTP.storbinary" or
  api = API::moduleImport("ftplib").getMember("FTP_TLS").getAnInstance().getMember("connect") and qn = "ftplib.FTP_TLS.connect" or
  api = API::moduleImport("ftplib").getMember("FTP_TLS").getAnInstance().getMember("login") and qn = "ftplib.FTP_TLS.login" or
  api = API::moduleImport("paramiko").getMember("SSHClient").getAnInstance().getMember("connect") and qn = "paramiko.SSHClient.connect" or
  api = API::moduleImport("paramiko").getMember("Transport").getAnInstance().getMember("connect") and qn = "paramiko.Transport.connect" or
  api = API::moduleImport("paramiko").getMember("SFTPClient").getMember("from_transport") and qn = "paramiko.SFTPClient.from_transport" or
  api = API::moduleImport("paramiko").getMember("SFTPClient").getAnInstance().getMember("get") and qn = "paramiko.SFTPClient.get" or
  api = API::moduleImport("paramiko").getMember("SFTPClient").getAnInstance().getMember("put") and qn = "paramiko.SFTPClient.put" or
  api = API::moduleImport("pycurl").getMember("Curl").getMember("perform") and qn = "pycurl.Curl.perform" or
  api = API::moduleImport("httplib2").getMember("Http").getAnInstance().getMember("request") and qn = "httplib2.Http.request" or
  api = API::moduleImport("mechanize").getMember("Browser").getAnInstance().getMember("open") and qn = "mechanize.Browser.open" or
  api = API::moduleImport("mechanize").getMember("urlopen") and qn = "mechanize.urlopen" or
  api = API::moduleImport("xmlrpc").getMember("client").getMember("ServerProxy") and qn = "xmlrpc.client.ServerProxy" or
  api = API::moduleImport("xmlrpc").getMember("client").getMember("Transport").getAnInstance().getMember("request") and qn = "xmlrpc.client.Transport.request" or
  api = API::moduleImport("zeep").getMember("Client") and qn = "zeep.Client" or
  api = API::moduleImport("suds").getMember("client").getMember("Client") and qn = "suds.client.Client" or
  api = API::moduleImport("feedparser").getMember("parse") and qn = "feedparser.parse" or
  api = API::moduleImport("wget").getMember("download") and qn = "wget.download" or
  api = API::moduleImport("urllib").getMember("robotparser").getMember("RobotFileParser").getAnInstance().getMember("set_url") and qn = "urllib.robotparser.RobotFileParser.set_url" or
  api = API::moduleImport("urllib").getMember("robotparser").getMember("RobotFileParser").getAnInstance().getMember("read") and qn = "urllib.robotparser.RobotFileParser.read" or
  api = API::moduleImport("ipaddress").getMember("ip_address") and qn = "ipaddress.ip_address" or
  api = API::moduleImport("ipaddress").getMember("ip_network") and qn = "ipaddress.ip_network" or
  api = API::moduleImport("cv2").getMember("VideoCapture") and qn = "cv2.VideoCapture" or
  api = API::moduleImport("pandas").getMember("read_csv") and qn = "pandas.read_csv" or
  api = API::moduleImport("pandas").getMember("read_json") and qn = "pandas.read_json" or
  api = API::moduleImport("pandas").getMember("read_html") and qn = "pandas.read_html" or
  api = API::moduleImport("urllib").getMember("request").getMember("build_opener").getAnInstance().getMember("open") and qn = "urllib.request.build_opener.open" or
  api = API::moduleImport("twisted").getMember("web").getMember("client").getMember("getPage") and qn = "twisted.web.client.getPage"
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
        