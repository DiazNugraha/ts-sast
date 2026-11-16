import { NewExpression, Node } from "ts-morph";
import { checkCWE95Eval } from "../rules";

export class NewExpressionService {
  constructor() {}

  analyze(node: NewExpression): IVulnerability[] {
    const exprText = node.getExpression().getText();

    const vulns: IVulnerability[] = [];

    if (checkCWE95Eval(exprText)) {
      const res = this.checkCWE95Eval(node);
      if (res) vulns.push(res);
    }

    return vulns;
  }

  private checkCWE95Eval(node: NewExpression): IVulnerability | null {
    const exprText = node.getExpression().getText();

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
}
