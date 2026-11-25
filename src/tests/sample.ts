export function oldFunctionName(a: number, b: number): number {
  a += 1;
  return a + b;
}

export const multiplier = (x: number) => x * 2;

import { exec } from "child_process";

export function runUserCommand(userInput: string) {
  // Vulnerable: Dynamic string concatenation / variable input
  exec("ls -la " + userInput);
  exec(`ls -la ${userInput}`);
}

const input = "";

// mysql_query(
//   "SELECT * FROM items WHERE owner = '" +
//     input +
//     "' AND itemname = '" +
//     input +
//     "'",
// );
//
// db.query(
//   // "SELECT id, email FROM users WHERE active = 1"
//   "SELECT * FROM items WHERE owner = '" +
//     input +
//     "' AND itemname = '" +
//     input +
//     "'",
// );

const query = `SELECT * FROM users WHERE email = '${req.body.email}'`;
// const query = `SELECT * FROM users WHERE email =`;
db.query(query);

const fullPath = path.join("/var/data/uploads", fileName);
fs.readFileSync(fullPath, "utf8");
