import cpp
import semmle.code.cpp.dataflow.DataFlow
class StringLiteralNode extends DataFlow::Node {
  StringLiteralNode() { this.asExpr() instanceof StringLiteral }
}
class MemcmpArgNode extends DataFlow::Node {
   MemcmpArgNode() {
    exists(FunctionCall fc |
      fc.getTarget().getName().regexpMatch(".*(str|mem|strn|b)*(cmp|str)*") and
      fc.getArgument(0) = this.asExpr() 
    )
 or
    exists(FunctionCall fc |
      fc.getTarget().getName().regexpMatch(".*(str|mem|strn|b)*(cmp|str)*") and
      fc.getArgument(1) = this.asExpr()
    )
  }
}

from StringLiteralNode src, MemcmpArgNode arg
where
  DataFlow::localFlow(src, arg)

select src.asExpr().(StringLiteral).toString()