export function oldFunctionName(a: number, b: number): number {
  a += 1;
  return a + b;
}

export const multiplier = (x: number) => x * 2;

import { exec } from "child_process";

export function runUserCommand(userInput: string) {
  // Vulnerable: Dynamic string concatenation / variable input
  // exec("ls -la " + userInput);
  exec(`ls -la ${userInput}`);
}
