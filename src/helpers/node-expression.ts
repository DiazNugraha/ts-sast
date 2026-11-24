import { CallExpression, Node, SyntaxKind } from "ts-morph";

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

export function isDynamicNode(node: Node): boolean {
  if (
    Node.isStringLiteral(node) ||
    Node.isNoSubstitutionTemplateLiteral(node) ||
    Node.isNumericLiteral(node)
  ) {
    return false;
  }

  // Template literal with expressions, e.g. `/uploads/${fileName}`
  if (Node.isTemplateExpression(node)) {
    return node.getTemplateSpans().length > 0;
  }

  // String concatenation, e.g. "/uploads/" + fileName
  if (
    Node.isBinaryExpression(node) &&
    node.getOperatorToken().getKind() === SyntaxKind.PlusToken
  ) {
    return true;
  }

  // Variables, property accesses (req.params.file), or function calls
  return (
    Node.isIdentifier(node) ||
    Node.isPropertyAccessExpression(node) ||
    Node.isCallExpression(node)
  );
}
