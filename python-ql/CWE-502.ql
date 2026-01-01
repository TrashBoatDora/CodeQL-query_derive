//number of apis 80
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("pickle").getMember("load") and qn = "pickle.load" or
  api = API::moduleImport("pickle").getMember("loads") and qn = "pickle.loads" or
  api = API::moduleImport("pickle").getMember("Unpickler") and qn = "pickle.Unpickler" or
  api = API::moduleImport("pickle").getMember("Unpickler").getMember("find_class") and qn = "pickle.Unpickler.find_class" or
  api = API::moduleImport("marshal").getMember("load") and qn = "marshal.load" or
  api = API::moduleImport("marshal").getMember("loads") and qn = "marshal.loads" or
  api = API::moduleImport("shelve").getMember("open") and qn = "shelve.open" or
  api = API::moduleImport("dill").getMember("load") and qn = "dill.load" or
  api = API::moduleImport("dill").getMember("loads") and qn = "dill.loads" or
  api = API::moduleImport("cloudpickle").getMember("load") and qn = "cloudpickle.load" or
  api = API::moduleImport("cloudpickle").getMember("loads") and qn = "cloudpickle.loads" or
  api = API::moduleImport("joblib").getMember("load") and qn = "joblib.load" or
  api = API::moduleImport("pandas").getMember("read_pickle") and qn = "pandas.read_pickle" or
  api = API::moduleImport("numpy").getMember("load") and qn = "numpy.load" or
  api = API::moduleImport("numpy").getMember("loadtxt") and qn = "numpy.loadtxt" or
  api = API::moduleImport("numpy").getMember("genfromtxt") and qn = "numpy.genfromtxt" or
  api = API::moduleImport("jsonpickle").getMember("decode") and qn = "jsonpickle.decode" or
  api = API::moduleImport("jsonpickle").getMember("loads") and qn = "jsonpickle.loads" or
  api = API::moduleImport("torch").getMember("load") and qn = "torch.load" or
  api = API::moduleImport("torch").getMember("jit").getMember("load") and qn = "torch.jit.load" or
  api = API::moduleImport("yaml").getMember("load") and qn = "yaml.load" or
  api = API::moduleImport("yaml").getMember("full_load") and qn = "yaml.full_load" or
  api = API::moduleImport("yaml").getMember("safe_load") and qn = "yaml.safe_load" or
  api = API::moduleImport("yaml").getMember("safe_load_all") and qn = "yaml.safe_load_all" or
  api = API::moduleImport("yaml").getMember("load_all") and qn = "yaml.load_all" or
  api = API::moduleImport("yaml").getMember("unsafe_load") and qn = "yaml.unsafe_load" or
  api = API::moduleImport("yaml").getMember("unsafe_load_all") and qn = "yaml.unsafe_load_all" or
  api = API::moduleImport("ast").getMember("literal_eval") and qn = "ast.literal_eval" or
  api = API::moduleImport("json").getMember("loads") and qn = "json.loads" or
  api = API::moduleImport("json").getMember("load") and qn = "json.load" or
  api = API::moduleImport("ujson").getMember("loads") and qn = "ujson.loads" or
  api = API::moduleImport("ujson").getMember("load") and qn = "ujson.load" or
  api = API::moduleImport("orjson").getMember("loads") and qn = "orjson.loads" or
  api = API::moduleImport("msgpack").getMember("unpackb") and qn = "msgpack.unpackb" or
  api = API::moduleImport("msgpack").getMember("unpack") and qn = "msgpack.unpack" or
  api = API::moduleImport("umsgpack").getMember("unpackb") and qn = "umsgpack.unpackb" or
  api = API::moduleImport("umsgpack").getMember("unpack") and qn = "umsgpack.unpack" or
  api = API::moduleImport("cbor2").getMember("loads") and qn = "cbor2.loads" or
  api = API::moduleImport("cbor2").getMember("load") and qn = "cbor2.load" or
  api = API::moduleImport("cbor").getMember("loads") and qn = "cbor.loads" or
  api = API::moduleImport("cbor").getMember("load") and qn = "cbor.load" or
  api = API::moduleImport("tomllib").getMember("loads") and qn = "tomllib.loads" or
  api = API::moduleImport("tomllib").getMember("load") and qn = "tomllib.load" or
  api = API::moduleImport("tomli").getMember("loads") and qn = "tomli.loads" or
  api = API::moduleImport("tomli").getMember("load") and qn = "tomli.load" or
  api = API::moduleImport("toml").getMember("loads") and qn = "toml.loads" or
  api = API::moduleImport("toml").getMember("load") and qn = "toml.load" or
  api = API::moduleImport("plistlib").getMember("loads") and qn = "plistlib.loads" or
  api = API::moduleImport("plistlib").getMember("load") and qn = "plistlib.load" or
  api = API::moduleImport("configparser").getMember("ConfigParser").getAnInstance().getMember("read") and qn = "configparser.ConfigParser.read" or
  api = API::moduleImport("configparser").getMember("ConfigParser").getAnInstance().getMember("read_file") and qn = "configparser.ConfigParser.read_file" or
  api = API::moduleImport("configparser").getMember("ConfigParser").getAnInstance().getMember("read_string") and qn = "configparser.ConfigParser.read_string" or
  api = API::moduleImport("pandas").getMember("read_json") and qn = "pandas.read_json" or
  api = API::moduleImport("pandas").getMember("read_csv") and qn = "pandas.read_csv" or
  api = API::moduleImport("pandas").getMember("read_parquet") and qn = "pandas.read_parquet" or
  api = API::moduleImport("pandas").getMember("read_feather") and qn = "pandas.read_feather" or
  api = API::moduleImport("pandas").getMember("read_hdf") and qn = "pandas.read_hdf" or
  api = API::moduleImport("pandas").getMember("read_excel") and qn = "pandas.read_excel" or
  api = API::moduleImport("skops").getMember("io").getMember("load") and qn = "skops.io.load" or
  api = API::moduleImport("tensorflow").getMember("saved_model").getMember("load") and qn = "tensorflow.saved_model.load" or
  api = API::moduleImport("tensorflow").getMember("keras").getMember("models").getMember("load_model") and qn = "tensorflow.keras.models.load_model" or
  api = API::moduleImport("keras").getMember("models").getMember("load_model") and qn = "keras.models.load_model" or
  api = API::moduleImport("mlflow").getMember("pyfunc").getMember("load_model") and qn = "mlflow.pyfunc.load_model" or
  api = API::moduleImport("mlflow").getMember("sklearn").getMember("load_model") and qn = "mlflow.sklearn.load_model" or
  api = API::moduleImport("xgboost").getMember("Booster").getAnInstance().getMember("load_model") and qn = "xgboost.Booster.load_model" or
  api = API::moduleImport("lightgbm").getMember("Booster") and qn = "lightgbm.Booster" or
  api = API::moduleImport("PIL").getMember("Image").getMember("open") and qn = "PIL.Image.open" or
  api = API::moduleImport("imageio").getMember("imread") and qn = "imageio.imread" or
  api = API::moduleImport("cv2").getMember("imread") and qn = "cv2.imread" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("parse") and qn = "xml.etree.ElementTree.parse" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("fromstring") and qn = "xml.etree.ElementTree.fromstring" or
  api = API::moduleImport("lxml").getMember("etree").getMember("parse") and qn = "lxml.etree.parse" or
  api = API::moduleImport("lxml").getMember("etree").getMember("fromstring") and qn = "lxml.etree.fromstring" or
  api = API::moduleImport("defusedxml").getMember("ElementTree").getMember("parse") and qn = "defusedxml.ElementTree.parse" or
  api = API::moduleImport("defusedxml").getMember("ElementTree").getMember("fromstring") and qn = "defusedxml.ElementTree.fromstring" or
  api = API::moduleImport("defusedxml").getMember("lxml").getMember("fromstring") and qn = "defusedxml.lxml.fromstring" or
  api = API::moduleImport("defusedxml").getMember("minidom").getMember("parseString") and qn = "defusedxml.minidom.parseString" or
  api = API::moduleImport("defusedxml").getMember("expatbuilder").getMember("parseString") and qn = "defusedxml.expatbuilder.parseString" or
  api = API::moduleImport("bson").getMember("BSON").getAnInstance().getMember("decode") and qn = "bson.BSON.decode" or
  api = API::moduleImport("bson").getMember("loads") and qn = "bson.loads" or
  api = API::moduleImport("bson").getMember("json_util").getMember("loads") and qn = "bson.json_util.loads" or
  api = API::moduleImport("sklearn").getMember("externals").getMember("joblib").getMember("load") and qn = "sklearn.externals.joblib.load" or
  api = API::moduleImport("pyarrow").getMember("deserialize") and qn = "pyarrow.deserialize"
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
        