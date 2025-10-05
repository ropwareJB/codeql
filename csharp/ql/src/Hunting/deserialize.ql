/**
 * @name Public call chains with taintable parameters to `Deserialize` calls.
 * @description Public methods with taintable parameters to `Deserialize` calls.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id cs/hunting/deserialize
 * @tags securitry
 */

import csharp
import DataFlow
import semmle.code.csharp.serialization.Deserializers

class UnsafeDeserializerCall extends Call{
  UnsafeDeserializerCall(){
    this.getTarget() instanceof UnsafeDeserializer
  }
}

class PublicMethod extends Method{
  PublicMethod(){
    this.fromSource()
    and this.isEffectivelyPublic()
  }
}

module DeserializableParameterConfig implements DataFlow::ConfigSig{
  predicate isSource(DataFlow::Node n){
    n instanceof DataFlow::ParameterNode
    and n.getEnclosingCallable() instanceof PublicMethod
  }
  predicate isSink(DataFlow::Node n){
    exists(UnsafeDeserializerCall deserializerCall |
      deserializerCall.getAnArgument() = n.asExpr()
      // 2025-10-05 ropwareJB: initially just focus on instances where there is no type constraint.
      // In the future, we should expand this to include type arguments that are sufficiently generic to house unsafe
      // members / variables of arbitrary types (Object).
      and not exists(deserializerCall.getAnnotatedType())
    )
  }
}
module DeserializableParameterFlow = TaintTracking::Global<DeserializableParameterConfig>;

class FlowSource extends DataFlow::ParameterNode{
  FlowSource(){
    DeserializableParameterConfig::isSource(this)
  }

  PublicMethod getCallable(){
    result = this.getEnclosingCallable()
  }

  string getAbsoluteReference(){
    exists(PublicMethod callable, int parameterIndex | 
        callable = this.getCallable()
        and DataFlow::parameterNode(callable.getParameter(parameterIndex)) = this
        and result = callable.getFullyQualifiedNameDebug() + "/" + callable.getNumberOfParameters() + ":" + parameterIndex.toString()
    )
  }
}

from
  FlowSource source,
  DataFlow::Node sink
where
  DeserializableParameterFlow::flow(source, sink)
select source, source.getAbsoluteReference() + ",$@", sink, "sink"