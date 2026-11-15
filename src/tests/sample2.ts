import { exec } from "child_process";

console.log("awokw");

export function runUserCommand(userInput: string) {
  exec(userInput);
}

import crypto from "crypto";

// This will trigger the CWE-328 rule
const hash = crypto.createHash("md5").update("xxx").digest("hex");
