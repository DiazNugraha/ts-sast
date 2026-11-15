import { CallExpression, SyntaxKind } from "ts-morph";

export function getOriginalFunctionName(
  node: CallExpression,
): string | undefined {
  const expression = node.getExpression();

  // Get the symbol of the expression (resolves variables, functions, and imports)
  let symbol = expression.getSymbol();

  if (!symbol) return undefined;

  // If it's an imported symbol that was renamed/aliased (e.g., `import { exec as foo }`),
  // get the original aliased symbol
  if (symbol.isAlias()) {
    symbol = symbol.getAliasedSymbol();
  }

  // Return the true original name of the function/method
  return symbol?.getName();
}

export function getFirstExpressionNode(node: CallExpression): CallExpression {
  const nodeDescendants = node.getDescendantsOfKind(SyntaxKind.CallExpression);

  if (nodeDescendants.length < 1) return node;

  return nodeDescendants[nodeDescendants.length - 1];
}
