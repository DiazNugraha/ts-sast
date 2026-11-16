export const checkCWE95Eval = (expressionText: string) => {
  const dangerousSinks = ["eval", "setTimeout", "setInterval", "Function"];

  return dangerousSinks.some(
    (ds) => expressionText == ds || expressionText.endsWith(`.${ds}`),
  );
};
