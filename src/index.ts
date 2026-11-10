import { Project } from "ts-morph";
import { EngineService } from "./utils";

function main() {
  const project = new Project({
    tsConfigFilePath: "tsconfig.json",
  });

  const sourceFile = project.getSourceFile("src/sample.ts");

  if (!sourceFile) throw Error("Failed to load source file");

  const engine = new EngineService();

  const results = engine.analyze(sourceFile);

  console.log(
    `Scan finished. Found ${results.length} security vulnerability/vulnerabilities:\n`,
  );
  results.forEach((f) => {
    console.log(`[${f.cwe}] ${f.ruleId}`);
    console.log(`  File: ${f.file}:${f.line}`);
    console.log(`  Msg:  ${f.message}\n`);
  });
}

main();
