package rules.injection

import rego.v1

# raise for any injection in bash/javascript
patterns.github contains "\\$\\{\\{[^\\}]+\\}\\}"
