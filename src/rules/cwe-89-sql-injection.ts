import { TemplateSpan } from "ts-morph";

export const checkCWE89SqlInjection = (expressionText: string) => {
  const dangerousSinks = ["mysql_query", "query", "db.query"];

  return dangerousSinks.some(
    (ds) => expressionText == ds || expressionText.endsWith(`.${ds}`),
  );
};

export const checkCWE89SqlInjectionText = (expressionText: string) => {
  const dangerousSinks = ["SELECT", "select"];

  return dangerousSinks.some((ds) => expressionText.includes(ds));
};

export const checkCWE89SqlInjectionInputs = (
  spans: TemplateSpan[],
): string | undefined => {
  const dangerousSinks = ["req.query.body", "req.body.email"];

  const spanTexts = spans.map((s) => s.getExpression().getText());

  return dangerousSinks.find((ds) => spanTexts.includes(ds));
};
