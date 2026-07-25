import { rmSync } from "node:fs";
import { resolve } from "node:path";

rmSync(resolve("out"), { force: true, recursive: true });
