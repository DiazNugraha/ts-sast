import { Node, VariableDeclaration } from "ts-morph";
import {
  checkCWE89SqlInjectionInputs,
  checkCWE89SqlInjectionText,
} from "../rules";

export class VariableDeclarationService {
  constructor() {}

  analyze(node: VariableDeclaration): IVulnerability[] {
    const initializer = node.getInitializer()?.getText() ?? "";

    const vulns: IVulnerability[] = [];

    if (checkCWE89SqlInjectionText(initializer)) {
      const res = this.checkCWE89SqlInjection(node);
      if (res) vulns.push(res);
    }

    return vulns;
  }

  private checkCWE89SqlInjection(
    node: VariableDeclaration,
  ): IVulnerability | null {
    const initializer = node.getInitializer();

    if (!initializer) return null;

    if (Node.isTemplateExpression(initializer)) {
      const spans = initializer.getTemplateSpans();

      const taintedSpan = checkCWE89SqlInjectionInputs(spans);
      if (taintedSpan) {
        return {
          file: node.getSourceFile().getFilePath(),
          ruleId: "javascript-lang-sqli-taint",
          cwe: "CWE-89",
          message: `Potential SQL Injection detected. Untrusted input flows into execution sink '${taintedSpan}'.`,
          line: node.getStartLineNumber(),
        };
      }
    }

    return null;
  }
}
