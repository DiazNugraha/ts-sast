export const checkCWE328WeakHash = (expressionText: string): boolean => {
  return (
    expressionText === "createHash" || expressionText.endsWith(".createHash")
  );
};
