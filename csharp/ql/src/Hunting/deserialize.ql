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
import semmle.code.csharp.serialization.Deserializers

Callable deserializers(){
    exists(UnsafeDeserializer d |
        result = d
    )
}

from ExplicitCast c, ConstructedType src, TypeParameter dest
where
  c.getExpr() instanceof ThisAccess and
  src = c.getExpr().getType() and
  dest = c.getTargetType() and
  dest = src.getUnboundGeneric().getATypeParameter()
select c,
  "Casting 'this' to $@, a type parameter of $@, masks an implicit type constraint that should be explicitly stated.",
  dest, dest.getName(), src, src.getName()
