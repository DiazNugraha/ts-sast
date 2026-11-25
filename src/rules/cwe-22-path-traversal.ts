export const checkCWE22PathTraversal = (methodName: string) => {
  const fileSinks = [
    "readFile",
    "readFileSync",
    "writeFile",
    "writeFileSync",
    "appendFile",
    "appendFileSync",
    "createReadStream",
    "createWriteStream",
    "unlink",
    "unlinkSync",
    "rm",
    "rmSync",
  ];

  const pathBuilders = ["join", "resolve"];

  return (
    fileSinks.some(
      (fs) => fs.includes(methodName) || methodName.endsWith(`.${fs}`),
    ) ||
    pathBuilders.some(
      (pb) => pb.includes(methodName) || methodName.endsWith(`.${pb}`),
    )
  );
};
