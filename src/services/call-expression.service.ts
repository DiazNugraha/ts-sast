import { CallExpression, Node, SyntaxKind } from "ts-morph";
import { checkCWE328WeakHash, checkCWE78cmdi } from "../rules";
import { getFirstExpressionNode } from "../helpers";

export class CallExpressionService {
  constructor() {}

  checkCommandInjection(node: CallExpression): IVulnerability | null {
    const expressionNode = getFirstExpressionNode(node);
    const exprText = expressionNode.getExpression().getText();

    if (checkCWE78cmdi(exprText)) {
      return this.checkCWE78cmdi(expressionNode);
    }

    if (checkCWE328WeakHash(exprText)) {
      return this.checkCWE328WeakHash(expressionNode);
    }

    return null;
  }

  private checkCWE78cmdi(node: CallExpression): IVulnerability | null {
    const exprText = node.getExpression().getText();

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

  private checkCWE328WeakHash(node: CallExpression): IVulnerability | null {
    const args = node.getArguments();
    if (args.length === 0) {
      return null;
    }

    const firstArgText = args[0].getText().toLowerCase();

    const weakAlgorithms = [
      "'md5'",
      '"md5"',
      "`md5`",
      "'sha1'",
      '"sha1"',
      "`sha1`",
    ];
    const isWeak = weakAlgorithms.some((algo) => firstArgText.includes(algo));

    if (isWeak) {
      return {
        file: node.getSourceFile().getFilePath(),
        ruleId: "cwe-328-weak-hash",
        cwe: "CWE-328",
        message: `Insecure cryptographic hash algorithm detected (${args[0].getText()}). MD5 and SHA-1 are cryptographically broken and vulnerable to collision attacks.`,
        line: node.getStartLineNumber(),
      };
    }

    return null;
  }
}
