import { exec } from "child_process";

console.log("awokw");

export function runUserCommand(userInput: string) {
  exec(userInput);
}
