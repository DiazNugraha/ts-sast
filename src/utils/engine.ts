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

export class EngineService {
  constructor(
    // private readonly engine: IEngine
  ) {}

  async analyze(sourceFile: SourceFile) {
    sourceFile.getStatements().map((node) => {
      this.nodeHandler(node);
    });
  }

  private async nodeHandler(node: Node<ts.Node>) {
    // Check Variable Declaration
    if (Node.isVariableDeclaration(node)) {
      this.handleVariableDeclaration(node);
    }

    // Check Variable Statement
    else if (Node.isVariableStatement(node)) {
      this.handleVariableStatement(node);
    }

    // Check Assignment Statements
    else if (
      Node.isBinaryExpression(node) &&
      node.getOperatorToken().getKind() == SyntaxKind.EqualsToken
    ) {
      this.handleAssigmentStatement(node);
    }

    // Check Call Expression
    else if (Node.isCallExpression(node)) {
      this.handleCallExpression(node);
    }

    // Check Expression Statement
    else if (Node.isExpressionStatement(node)) {
      this.handleExpressionStatement(node);
    }

    // Check Function Declaration
    else if (Node.isFunctionDeclaration(node)) {
      this.handleFunctionDeclaration(node);
    }

    // Check Return Statement
    else if (Node.isReturnStatement(node)) {
      this.handleReturnStatement(node);
    }
  }

  private async handleVariableDeclaration(node: VariableDeclaration) {
    console.log(
      `[VariableDeclaration] Found var: ${node.getName()} = ${node.getInitializer()?.getText()}`,
    );
  }

  private async handleVariableStatement(node: VariableStatement) {
    node.getDeclarations().map((n) => {
      this.handleVariableDeclaration(n);
    });
  }

  private async handleAssigmentStatement(node: BinaryExpression) {
    console.log(
      `[AssignmentStatement] Found assignment: ${node.getLeft().getText()} = ${node.getRight().getText()}`,
    );
  }

  private async handleBinaryExpression(node: BinaryExpression) {
    console.log(
      `[BinaryExpression] Found Binary Expression: ${node.getLeft().getText()} ${node.getOperatorToken().getText()} ${node.getRight().getText()}`,
    );
  }

  private async handleExpressionStatement(node: ExpressionStatement) {
    node.forEachChild((n) => {
      if (Node.isBinaryExpression(n)) {
        this.handleBinaryExpression(n);
      }
    });
  }

  private async handleCallExpression(node: CallExpression) {
    const joinArguments = node
      .getArguments()
      .map((argument) => argument.getText())
      .join(", ");

    console.log(
      `[CallExpression] Found call on: ${node.getText()}; arguments: ${joinArguments}`,
    );
  }

  private async handleReturnStatement(node: ReturnStatement) {
    console.log(`[ReturnStatement] Found return on: ${node.getText()}`);
  }

  private async handleFunctionDeclaration(node: FunctionDeclaration) {
    const params = node
      .getParameters()
      .map((e) => `${e.getName()}: ${e.getType().getText()}`)
      .join(", ");

    console.log(
      `[FunctionDeclaration] Found declaration: ${node.getName()}(${params})`,
    );

    node.forEachDescendant((nd) => {
      if (Node.isNode(nd)) {
        nd.forEachDescendant((n) => {
          this.nodeHandler(n);
        });
      }
    });
  }
}
