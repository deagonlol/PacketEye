// React 19 moved the JSX namespace under `React.JSX`. Re-expose it globally so
// existing `JSX.Element` return annotations keep working.
import 'react'

declare global {
  namespace JSX {
    type Element = React.JSX.Element
    type ElementClass = React.JSX.ElementClass
    type ElementAttributesProperty = React.JSX.ElementAttributesProperty
    type ElementChildrenAttribute = React.JSX.ElementChildrenAttribute
    type IntrinsicElements = React.JSX.IntrinsicElements
    type IntrinsicAttributes = React.JSX.IntrinsicAttributes
    type LibraryManagedAttributes<C, P> = React.JSX.LibraryManagedAttributes<C, P>
  }
}
