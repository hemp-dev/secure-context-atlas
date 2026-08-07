/**
 * @name Dynamic expression evaluation
 * @description Finds calls to Python's dynamic evaluation primitives. Confirm the source, evaluation context and allowlist before treating the result as a finding.
 * @kind problem
 * @id secure-context-atlas/injection/dynamic-eval
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @tags security external/cwe/cwe-917
 */
import python

from Call call, Name name
where
  call.getFunc() = name and
  (name.getId() = "eval" or name.getId() = "exec" or name.getId() = "compile")
select call, "Dynamic evaluation reaches an expression boundary; validate the source and restrict the evaluation context."
