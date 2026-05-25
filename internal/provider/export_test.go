package provider

import "github.com/winebarrel/terraform-provider-iamencode/internal/iamcatalog"

// Exported for external (_test package) tests. Only compiled at test time,
// so the package's public API stays unchanged.

var (
	AttrValueToNative  = attrValueToNative
	ElementsToNative   = elementsToNative
	AttributesToNative = attributesToNative

	// PolicyStrictFunction.catalog is unexported, so tests can't inject a
	// fake catalog by constructing the struct literal directly.
	NewPolicyStrictFunctionForTest = func(c *iamcatalog.Catalog) PolicyStrictFunction {
		return PolicyStrictFunction{catalog: c}
	}
)
