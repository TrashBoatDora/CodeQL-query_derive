import python
import semmle.python.Flow as Flow

from Call call, Flow::ControlFlowNode n, Flow::BasicBlock bb
where n = call.getAFlowNode() and bb = n.getBasicBlock()
select call, bb, "in function: " + bb.getScope().getName()