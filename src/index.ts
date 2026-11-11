import { Project } from "ts-morph";
import { EngineService } from "./utils";
import { CallExpressionService } from "./services";
import path from "path";

function main() {
  const project = new Project({
    tsConfigFilePath: "tsconfig.json",
  });

  const callExpressionService = new CallExpressionService();
  const engine = new EngineService(callExpressionService);

  const targetFiles = project.getSourceFiles().filter((sourceFile) => {
    const filePath = sourceFile.getFilePath();
    // Normalize path separators and check if it sits inside src/tests
    return filePath.includes(path.normalize("src/tests/"));
  });

  const results: IVulnerability[] = [];
  targetFiles.map((sourceFile) => {
    const res = engine.analyze(sourceFile);
    results.push(...res);
  });

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
