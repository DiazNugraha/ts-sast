import { Project } from "ts-morph";
import { EngineService } from "./utils";

function main() {
  const project = new Project({
    tsConfigFilePath: "tsconfig.json",
  });

  const sourceFile = project.getSourceFile("src/sample.ts");

  if (!sourceFile) throw Error("Failed to load source file");

  const engine = new EngineService();

  engine.analyze(sourceFile);
}

main();
