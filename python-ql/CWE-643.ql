//number of apis 28
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("lxml").getMember("etree").getMember("XPath") and qn = "lxml.etree.XPath" or
  api = API::moduleImport("lxml").getMember("etree").getMember("ETXPath") and qn = "lxml.etree.ETXPath" or
  api = API::moduleImport("lxml").getMember("etree").getMember("XPathEvaluator") and qn = "lxml.etree.XPathEvaluator" or
  api = API::moduleImport("lxml").getMember("etree").getMember("_Element").getMember("xpath") and qn = "lxml.etree._Element.xpath" or
  api = API::moduleImport("lxml").getMember("etree").getMember("_ElementTree").getMember("xpath") and qn = "lxml.etree._ElementTree.xpath" or
  api = API::moduleImport("lxml").getMember("objectify").getMember("ObjectifiedElement").getMember("xpath") and qn = "lxml.objectify.ObjectifiedElement.xpath" or
  api = API::moduleImport("lxml").getMember("etree").getMember("XSLT") and qn = "lxml.etree.XSLT" or
  api = API::moduleImport("lxml").getMember("html").getMember("HtmlElement").getMember("xpath") and qn = "lxml.html.HtmlElement.xpath" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("Element").getMember("find") and qn = "xml.etree.ElementTree.Element.find" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("Element").getMember("findall") and qn = "xml.etree.ElementTree.Element.findall" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("Element").getMember("iterfind") and qn = "xml.etree.ElementTree.Element.iterfind" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("Element").getMember("iter") and qn = "xml.etree.ElementTree.Element.iter" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("ElementTree").getAnInstance().getMember("find") and qn = "xml.etree.ElementTree.ElementTree.find" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("ElementTree").getAnInstance().getMember("findall") and qn = "xml.etree.ElementTree.ElementTree.findall" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementTree").getMember("ElementTree").getAnInstance().getMember("iterfind") and qn = "xml.etree.ElementTree.ElementTree.iterfind" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementPath").getMember("find") and qn = "xml.etree.ElementPath.find" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementPath").getMember("findall") and qn = "xml.etree.ElementPath.findall" or
  api = API::moduleImport("xml").getMember("etree").getMember("ElementPath").getMember("iterfind") and qn = "xml.etree.ElementPath.iterfind" or
  api = API::moduleImport("elementpath").getMember("select") and qn = "elementpath.select" or
  api = API::moduleImport("elementpath").getMember("XPath1Parser").getAnInstance().getMember("parse") and qn = "elementpath.XPath1Parser.parse" or
  api = API::moduleImport("elementpath").getMember("XPath2Parser").getAnInstance().getMember("parse") and qn = "elementpath.XPath2Parser.parse" or
  api = API::moduleImport("parsel").getMember("Selector").getAnInstance().getMember("xpath") and qn = "parsel.Selector.xpath" or
  api = API::moduleImport("scrapy").getMember("selector").getMember("Selector").getAnInstance().getMember("xpath") and qn = "scrapy.selector.Selector.xpath" or
  api = API::moduleImport("defusedxml").getMember("ElementTree").getMember("parse") and qn = "defusedxml.ElementTree.parse" or
  api = API::moduleImport("defusedxml").getMember("ElementTree").getMember("fromstring") and qn = "defusedxml.ElementTree.fromstring" or
  api = API::moduleImport("defusedxml").getMember("ElementTree").getMember("iterparse") and qn = "defusedxml.ElementTree.iterparse" or
  api = API::moduleImport("defusedxml").getMember("lxml").getMember("fromstring") and qn = "defusedxml.lxml.fromstring" or
  api = API::moduleImport("defusedxml").getMember("lxml").getMember("parse") and qn = "defusedxml.lxml.parse" or
  api = API::moduleImport("libxml2").getMember("xpathNewContext") and qn = "libxml2.xpathNewContext" or
  api = API::moduleImport("libxml2").getMember("xmlXPathContext").getAnInstance().getMember("xpathEval") and qn = "libxml2.xmlXPathContext.xpathEval" or
  api = API::moduleImport("libxml2").getMember("xmlDoc").getAnInstance().getMember("xpathEval") and qn = "libxml2.xmlDoc.xpathEval" or
  api = API::moduleImport("libxml2").getMember("xmlNode").getAnInstance().getMember("xpathEval") and qn = "libxml2.xmlNode.xpathEval" or
  api = API::moduleImport("elementpath").getMember("compile") and qn = "elementpath.compile" or
  api = API::moduleImport("elementpath").getMember("XPath3Parser").getAnInstance().getMember("parse") and qn = "elementpath.XPath3Parser.parse" or
  api = API::moduleImport("libxml2").getMember("xpathNewContext") and qn = "libxml2.xpathNewContext" or
  api = API::moduleImport("libxml2").getMember("xmlXPathContext").getAnInstance().getMember("xpathEval") and qn = "libxml2.xmlXPathContext.xpathEval" or
  api = API::moduleImport("libxml2").getMember("xmlDoc").getAnInstance().getMember("xpathEval") and qn = "libxml2.xmlDoc.xpathEval" or
  api = API::moduleImport("libxml2").getMember("xmlNode").getAnInstance().getMember("xpathEval") and qn = "libxml2.xmlNode.xpathEval"
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
        