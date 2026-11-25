import { CallExpression, Node, SyntaxKind } from "ts-morph";
import {
  checkCWE22PathTraversal,
  checkCWE328WeakHash,
  checkCWE78cmdi,
  checkCWE89SqlInjection,
  checkCWE95Eval,
} from "../rules";
import { getFirstExpressionNode, isDynamicNode } from "../helpers";

export class CallExpressionService {
  constructor() {}

  analyze(node: CallExpression): IVulnerability[] {
    const expressionNode = getFirstExpressionNode(node);
    const exprText = expressionNode.getExpression().getText();

    const vulns: IVulnerability[] = [];

    if (checkCWE78cmdi(exprText)) {
      const res = this.checkCWE78cmdi(expressionNode);
      if (res) vulns.push(res);
    }

    if (checkCWE95Eval(exprText)) {
      const res = this.checkCWE95Eval(expressionNode);
      if (res) vulns.push(res);
    }

    if (checkCWE328WeakHash(exprText)) {
      const res = this.checkCWE328WeakHash(expressionNode);
      if (res) vulns.push(res);
    }

    if (checkCWE89SqlInjection(exprText)) {
      const res = this.checkCWE89SqlInjection(expressionNode);
      if (res) vulns.push(res);
    }

    if (checkCWE22PathTraversal(exprText)) {
      const res = this.checkCWE22PathTraversal(expressionNode);
      if (res) vulns.push(res);
    }

    return vulns;
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

    if (!isLiteral || isConcatinated) {
      return {
        file: node.getSourceFile().getFilePath(),
        ruleId: "javascript-lang-cmdi-dangerous-spawn-shell-taint",
        cwe: "CWE-78",
        message: `Potential OS Command Injection detected. Untrusted input flows into execution sink '${exprText}'.`,
        line: node.getStartLineNumber(),
      };
    }

    return null;
  }

  private checkCWE95Eval(node: CallExpression): IVulnerability | null {
    const exprText = node.getExpression().getText();

    if (exprText === "eval") {
      const args = node.getArguments();
      if (args.length > 0) {
        const firstArg = args[0];
        const isLiteral =
          Node.isStringLiteral(firstArg) ||
          Node.isNoSubstitutionTemplateLiteral(firstArg);

        if (!isLiteral || Node.isBinaryExpression(firstArg)) {
          return {
            file: node.getSourceFile().getFilePath(),
            ruleId: "cwe-95-eval-injection",
            cwe: "CWE-95",
            message:
              "Potential Eval Injection detected. Dynamic or untrusted input is passed into `eval()`.",
            line: node.getStartLineNumber(),
          };
        }
      }
    }

    if (exprText === "setTimeout" || exprText === "setInterval") {
      const args = node.getArguments();

      if (
        args.length > 0 &&
        (Node.isStringLiteral(args[0]) || Node.isBinaryExpression(args[0]))
      ) {
        return {
          file: node.getSourceFile().getFilePath(),
          ruleId: "cwe-95-eval-timer",
          cwe: "CWE-95",
          message:
            "Code injection risk: passing a string argument to timers acts like `eval()`. Use a callback function instead.",
          line: node.getStartLineNumber(),
        };
      }
    }

    if (Node.isNewExpression(node)) {
      if (exprText === "Function") {
        return {
          file: node.getSourceFile().getFilePath(),
          ruleId: "cwe-95-dynamic-function",
          cwe: "CWE-95",
          message:
            "Use of `new Function()` constructor is equivalent to `eval()` and can lead to arbitrary code execution.",
          line: node.getStartLineNumber(),
        };
      }
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

  private checkCWE89SqlInjection(node: CallExpression): IVulnerability | null {
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

    if (!isLiteral || isConcatinated) {
      return {
        file: node.getSourceFile().getFilePath(),
        ruleId: "javascript-lang-sqli-taint",
        cwe: "CWE-89",
        message: `Potential SQL Injection detected. Untrusted input flows into execution sink '${exprText}'.`,
        line: node.getStartLineNumber(),
      };
    }

    return null;
  }

  checkCWE22PathTraversal(node: CallExpression): IVulnerability | null {
    const methodName = node.getText();

    const args = node.getArguments();
    if (args.length === 0) return null;

    const hasDynamicInput = args.some((arg) => isDynamicNode(arg));

    if (hasDynamicInput) {
      return {
        file: node.getSourceFile().getFilePath(),
        ruleId: "cwe-22-path-traversal",
        cwe: "CWE-22",
        message: `Potential Path Traversal detected in '${methodName}'. Verify and canonicalize the resolved path against a safe base directory.`,
        line: node.getStartLineNumber(),
      };
    }

    return null;
  }
}
