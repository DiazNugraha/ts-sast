export const checkCWE78cmdi = (expressionText: string): boolean => {
  const dangerousSinks = [
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "shell.exec", // common in shelljs
  ];

  return dangerousSinks.some(
    (ds) => expressionText == ds || expressionText.endsWith(`.${ds}`),
  );
};
