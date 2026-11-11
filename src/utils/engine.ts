import {
  BinaryExpression,
  CallExpression,
  ExpressionStatement,
  FunctionDeclaration,
  Node,
  ReturnStatement,
  SourceFile,
  SyntaxKind,
  ts,
  VariableDeclaration,
  VariableStatement,
} from "ts-morph";
import { CallExpressionService } from "../services";

export class EngineService {
  constructor(private readonly callExpressionService: CallExpressionService) {}

  analyze(sourceFile: SourceFile): IVulnerability[] {
    const vulns: IVulnerability[] = [];

    sourceFile.getStatements().map((node) => {
      const res = this.nodeHandler(node);
      if (Array.isArray(res)) {
        vulns.push(...res);
      } else if (res !== null) {
        vulns.push(res);
      }
    });

    return vulns;
  }

  private nodeHandler(
    node: Node<ts.Node>,
  ): IVulnerability | IVulnerability[] | null {
    // Check Variable Declaration
    if (Node.isVariableDeclaration(node)) {
      return this.handleVariableDeclaration(node);
    }

    // Check Variable Statement
    else if (Node.isVariableStatement(node)) {
      return this.handleVariableStatement(node);
    }

    // Check Assignment Statements
    else if (
      Node.isBinaryExpression(node) &&
      node.getOperatorToken().getKind() == SyntaxKind.EqualsToken
    ) {
      return this.handleAssigmentStatement(node);
    }

    // Check Call Expression
    else if (Node.isCallExpression(node)) {
      return this.handleCallExpression(node);
    }

    // Check Expression Statement
    else if (Node.isExpressionStatement(node)) {
      return this.handleExpressionStatement(node);
    }

    // Check Function Declaration
    else if (Node.isFunctionDeclaration(node)) {
      return this.handleFunctionDeclaration(node);
    }

    // Check Return Statement
    else if (Node.isReturnStatement(node)) {
      return this.handleReturnStatement(node);
    }

    return null;
  }

  private handleFunctionDeclaration(
    node: FunctionDeclaration,
  ): IVulnerability[] {
    // const params = node
    //   .getParameters()
    //   .map((e) => `${e.getName()}: ${e.getType().getText()}`)
    //   .join(", ");
    //
    // console.log(
    //   `[FunctionDeclaration] Found declaration: ${node.getName()}(${params})`,
    // );

    const vulns: IVulnerability[] = [];

    node.forEachChild((nd) => {
      if (Node.isNode(nd)) {
        nd.forEachDescendant((n) => {
          const res = this.nodeHandler(n);
          if (Array.isArray(res)) {
            vulns.push(...res);
          } else if (res !== null) {
            vulns.push(res);
          }
        });
      }
    });

    return vulns;
  }

  private handleVariableStatement(node: VariableStatement): IVulnerability[] {
    const vulns: IVulnerability[] = [];

    node.getDeclarations().map((n) => {
      const res = this.handleVariableDeclaration(n);
      if (res) vulns.push(res);
    });

    return vulns;
  }

  private handleExpressionStatement(
    node: ExpressionStatement,
  ): IVulnerability[] {
    const vulns: IVulnerability[] = [];

    node.forEachChild((n) => {
      if (Node.isBinaryExpression(n)) {
        const res = this.handleBinaryExpression(n);
        if (res) vulns.push(res);
      }
    });

    return vulns;
  }

  private handleVariableDeclaration(
    node: VariableDeclaration,
  ): IVulnerability | null {
    // console.log(
    //   `[VariableDeclaration] Found var: ${node.getName()} = ${node.getInitializer()?.getText()}`,
    // );

    return null;
  }

  private handleAssigmentStatement(
    node: BinaryExpression,
  ): IVulnerability | null {
    // console.log(
    //   `[AssignmentStatement] Found assignment: ${node.getLeft().getText()} = ${node.getRight().getText()}`,
    // );

    return null;
  }

  private handleBinaryExpression(
    node: BinaryExpression,
  ): IVulnerability | null {
    // console.log(
    //   `[BinaryExpression] Found Binary Expression: ${node.getLeft().getText()} ${node.getOperatorToken().getText()} ${node.getRight().getText()}`,
    // );

    return null;
  }

  private handleCallExpression(node: CallExpression): IVulnerability | null {
    return this.callExpressionService.checkCommandInjection(node);
  }

  private handleReturnStatement(node: ReturnStatement): IVulnerability | null {
    // console.log(`[ReturnStatement] Found return on: ${node.getText()}`);
    return null;
  }
}
