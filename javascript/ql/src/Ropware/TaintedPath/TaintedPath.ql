/**
 * @name Import External Script
 * @description Imports an external script that is remote-controlled.
 * @kind path-problem
 * @problem.severity error
 * @id ropware/js/path-injection
 * @precision high
 */

import javascript
import semmle.javascript.security.dataflow.TaintedPathQuery
import DataFlow::PathGraph

/**
 * The `x` in `import(x)`.
 */
class DynamicImportArg extends Sink{
    DynamicImportArg(){
        exists(DynamicImportExpr anImport |
            this = DataFlow::exprNode(anImport.getChildExpr(0))
        )
    }
}

/**
 * A call to script.js to import a module dynamically, which may include a `fetch`.
 * 
 * ```
    var scriptjs = require('scriptjs');
    scriptjs("https://example/somemodule, function(){});
 * ```
 */
class ScriptJsArg extends Sink{
    ScriptJsArg(){
        this = DataFlow::moduleImport("scriptjs").getACall().getArgument(0)
    }
}

class SpecializedDataFlow extends Configuration{
    override predicate isAdditionalFlowStep(
        DataFlow::Node src, DataFlow::Node dst, DataFlow::FlowLabel srclabel,
        DataFlow::FlowLabel dstlabel
    ) {
        this.(Configuration).isAdditionalFlowStep(src, dst, srclabel, dstlabel)
        or (
            exists(ArrayExpr array |
                array = dst.asExpr()
                and array.getAChild() = src.asExpr()
            )
        )
    }
}

from
    SpecializedDataFlow cfg,
    DataFlow::PathNode source,
    DataFlow::PathNode sink
where
    cfg.hasFlowPath(source, sink)
select
    sink.getNode(), source, sink, "This path depends on a $@.",
    source.getNode(), "user-provided value"