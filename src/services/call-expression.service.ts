import { CallExpression, Node, SyntaxKind } from "ts-morph";

export class CallExpressionService {
  constructor() {}

  checkCommandInjection(node: CallExpression): IVulnerability | null {
    const dangerousSinks = [
      "exec",
      "execSync",
      "spawn",
      "spawnSync",
      "shell.exec", // common in shelljs
    ];

    const exprText = node.getExpression().getText();

    const isSinkMatch = dangerousSinks.some(
      (ds) => exprText == ds || exprText.endsWith(`.${ds}`),
    );

    if (!isSinkMatch) return null;

    const args = node.getArguments();
    if (args.length === 0) return null;

    const firstArg = args[0];
    const isLiteral =
      Node.isStringLiteral(firstArg) ||
      Node.isNoSubstitutionTemplateLiteral(firstArg);

    const isConcatinated =
      Node.isBinaryExpression(firstArg) &&
      firstArg.getOperatorToken().getKind() === SyntaxKind.PlusToken;

    if (!isLiteral) {
      if (isConcatinated) {
        return {
          file: node.getSourceFile().getFilePath(),
          ruleId: "javascript-lang-cmdi-dangerous-spawn-shell-taint",
          cwe: "CWE-78",
          message: `Potential OS Command Injection detected. Untrusted input flows into execution sink '${exprText}'.`,
          line: node.getStartLineNumber(),
        };
      }

      return {
        file: node.getSourceFile().getFilePath(),
        ruleId: "javascript-lang-cmdi-detect-eval-taint",
        cwe: "CWE-95",
        message: `Potential OS Command Injection detected. Untrusted input flows into execution sink '${exprText}'.`,
        line: node.getStartLineNumber(),
      };
    }

    return null;
  }
}
