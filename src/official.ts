import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

export interface OfficialProject {
  name: string;
  brands: string[];
  domains: string[];
  x: string[];
}

const here = dirname(fileURLToPath(import.meta.url));

export function loadOfficialProjects(path = resolve(here, "../data/official-projects.json")): OfficialProject[] {
  const raw = JSON.parse(readFileSync(path, "utf8")) as { projects: OfficialProject[] };
  return raw.projects;
}
