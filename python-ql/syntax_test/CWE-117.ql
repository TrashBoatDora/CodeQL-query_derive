//number of apis 70
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("logging").getMember("getLogger") and qn = "logging.getLogger" or
  api = API::moduleImport("logging").getMember("Logger").getAnInstance().getMember("debug") and qn = "logging.Logger.debug" or
  api = API::moduleImport("logging").getMember("Logger").getAnInstance().getMember("info") and qn = "logging.Logger.info" or
  api = API::moduleImport("logging").getMember("Logger").getAnInstance().getMember("warning") and qn = "logging.Logger.warning" or
  api = API::moduleImport("logging").getMember("Logger").getAnInstance().getMember("error") and qn = "logging.Logger.error" or
  api = API::moduleImport("logging").getMember("Logger").getAnInstance().getMember("exception") and qn = "logging.Logger.exception" or
  api = API::moduleImport("logging").getMember("Logger").getAnInstance().getMember("critical") and qn = "logging.Logger.critical" or
  api = API::moduleImport("logging").getMember("Logger").getAnInstance().getMember("log") and qn = "logging.Logger.log" or
  api = API::moduleImport("logging").getMember("Logger").getAnInstance().getMember("getChild") and qn = "logging.Logger.getChild" or
  api = API::moduleImport("logging").getMember("debug") and qn = "logging.debug" or
  api = API::moduleImport("logging").getMember("info") and qn = "logging.info" or
  api = API::moduleImport("logging").getMember("warning") and qn = "logging.warning" or
  api = API::moduleImport("logging").getMember("error") and qn = "logging.error" or
  api = API::moduleImport("logging").getMember("exception") and qn = "logging.exception" or
  api = API::moduleImport("logging").getMember("critical") and qn = "logging.critical" or
  api = API::moduleImport("logging").getMember("log") and qn = "logging.log" or
  api = API::moduleImport("logging").getMember("warn") and qn = "logging.warn" or
  api = API::moduleImport("logging").getMember("basicConfig") and qn = "logging.basicConfig" or
  api = API::moduleImport("logging").getMember("captureWarnings") and qn = "logging.captureWarnings" or
  api = API::moduleImport("logging").getMember("config").getMember("dictConfig") and qn = "logging.config.dictConfig" or
  api = API::moduleImport("logging").getMember("config").getMember("fileConfig") and qn = "logging.config.fileConfig" or
  api = API::moduleImport("logging").getMember("LoggerAdapter").getAnInstance().getMember("debug") and qn = "logging.LoggerAdapter.debug" or
  api = API::moduleImport("logging").getMember("LoggerAdapter").getAnInstance().getMember("info") and qn = "logging.LoggerAdapter.info" or
  api = API::moduleImport("logging").getMember("LoggerAdapter").getAnInstance().getMember("warning") and qn = "logging.LoggerAdapter.warning" or
  api = API::moduleImport("logging").getMember("LoggerAdapter").getAnInstance().getMember("error") and qn = "logging.LoggerAdapter.error" or
  api = API::moduleImport("logging").getMember("LoggerAdapter").getAnInstance().getMember("exception") and qn = "logging.LoggerAdapter.exception" or
  api = API::moduleImport("logging").getMember("LoggerAdapter").getAnInstance().getMember("critical") and qn = "logging.LoggerAdapter.critical" or
  api = API::moduleImport("logging").getMember("LoggerAdapter").getAnInstance().getMember("log") and qn = "logging.LoggerAdapter.log" or
  api = API::moduleImport("logging").getMember("Formatter") and qn = "logging.Formatter" or
  api = API::moduleImport("logging").getMember("makeLogRecord") and qn = "logging.makeLogRecord" or
  api = API::moduleImport("logging").getMember("StreamHandler") and qn = "logging.StreamHandler" or
  api = API::moduleImport("logging").getMember("FileHandler") and qn = "logging.FileHandler" or
  api = API::moduleImport("logging").getMember("NullHandler") and qn = "logging.NullHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("WatchedFileHandler") and qn = "logging.handlers.WatchedFileHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("RotatingFileHandler") and qn = "logging.handlers.RotatingFileHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("TimedRotatingFileHandler") and qn = "logging.handlers.TimedRotatingFileHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("SocketHandler") and qn = "logging.handlers.SocketHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("DatagramHandler") and qn = "logging.handlers.DatagramHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("SysLogHandler") and qn = "logging.handlers.SysLogHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("NTEventLogHandler") and qn = "logging.handlers.NTEventLogHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("SMTPHandler") and qn = "logging.handlers.SMTPHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("HTTPHandler") and qn = "logging.handlers.HTTPHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("QueueHandler") and qn = "logging.handlers.QueueHandler" or
  api = API::moduleImport("logging").getMember("handlers").getMember("MemoryHandler") and qn = "logging.handlers.MemoryHandler" or
  api = API::moduleImport("tornado").getMember("log").getMember("gen_log") and qn = "tornado.log.gen_log" or
  api = API::moduleImport("tornado").getMember("log").getMember("app_log") and qn = "tornado.log.app_log" or
  api = API::moduleImport("tornado").getMember("log").getMember("access_log") and qn = "tornado.log.access_log" or
  api = API::moduleImport("syslog").getMember("syslog") and qn = "syslog.syslog" or
  api = API::moduleImport("loguru").getMember("logger").getMember("debug") and qn = "loguru.logger.debug" or
  api = API::moduleImport("loguru").getMember("logger").getMember("info") and qn = "loguru.logger.info" or
  api = API::moduleImport("loguru").getMember("logger").getMember("warning") and qn = "loguru.logger.warning" or
  api = API::moduleImport("loguru").getMember("logger").getMember("error") and qn = "loguru.logger.error" or
  api = API::moduleImport("loguru").getMember("logger").getMember("exception") and qn = "loguru.logger.exception" or
  api = API::moduleImport("loguru").getMember("logger").getMember("critical") and qn = "loguru.logger.critical" or
  api = API::moduleImport("loguru").getMember("logger").getMember("success") and qn = "loguru.logger.success" or
  api = API::moduleImport("loguru").getMember("logger").getMember("add") and qn = "loguru.logger.add" or
  api = API::moduleImport("loguru").getMember("logger").getMember("bind") and qn = "loguru.logger.bind" or
  api = API::moduleImport("structlog").getMember("get_logger") and qn = "structlog.get_logger" or
  api = API::moduleImport("structlog").getMember("stdlib").getMember("get_logger") and qn = "structlog.stdlib.get_logger" or
  api = API::moduleImport("structlog").getMember("configure") and qn = "structlog.configure" or
  api = API::moduleImport("structlog").getMember("processors").getMember("JSONRenderer") and qn = "structlog.processors.JSONRenderer" or
  api = API::moduleImport("rich").getMember("logging").getMember("RichHandler") and qn = "rich.logging.RichHandler" or
  api = API::moduleImport("pythonjsonlogger").getMember("jsonlogger").getMember("JsonFormatter") and qn = "pythonjsonlogger.jsonlogger.JsonFormatter" or
  api = API::moduleImport("warnings").getMember("warn") and qn = "warnings.warn" or
  api = API::builtin("print") and qn = "print" or
  api = API::moduleImport("sys").getMember("stdout").getMember("write") and qn = "sys.stdout.write" or
  api = API::moduleImport("sys").getMember("stderr").getMember("write") and qn = "sys.stderr.write" or
  api = API::builtin("repr") and qn = "repr" or
  api = API::moduleImport("re").getMember("sub") and qn = "re.sub" or
  api = API::moduleImport("json").getMember("dumps") and qn = "json.dumps" or
  api = API::moduleImport("structlog") and qn = "structlog.*"
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
        