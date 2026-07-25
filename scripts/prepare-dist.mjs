import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

mkdirSync(resolve("dist"), { recursive: true });
