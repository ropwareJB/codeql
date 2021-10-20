/**
 * @name Android Fragment injection in PreferenceActivity
 * @description An insecure implementation of the isValidFragment method
 *              of the PreferenceActivity class may lead to Fragment injection.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/android/fragment-injection-preference-activity
 * @tags security
 *       external/cwe/cwe-470
 */

import java
import semmle.code.java.security.FragmentInjection

from IsValidFragmentMethod m
where m.isUnsafe()
select m,
  "The 'isValidFragment' method always returns true. This makes the exported Activity $@ vulnerable to Fragment Injection.",
  m.getDeclaringType(), m.getDeclaringType().getName()
