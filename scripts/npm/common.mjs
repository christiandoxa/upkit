import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));

export const repoRoot = path.resolve(scriptDir, "..", "..");
export const cargoTomlPath = path.join(repoRoot, "Cargo.toml");
export const npmScope = "@christiandoxa";
export const mainPackageName = `${npmScope}/upkit`;
export const packageVersionPattern =
  /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;

export const platformPackages = [
  {
    target: "x86_64-unknown-linux-gnu",
    packageName: `${npmScope}/upkit-linux-x64`,
    os: "linux",
    cpu: "x64",
    binaryFileName: "upkit",
  },
  {
    target: "aarch64-unknown-linux-gnu",
    packageName: `${npmScope}/upkit-linux-arm64`,
    os: "linux",
    cpu: "arm64",
    binaryFileName: "upkit",
  },
  {
    target: "x86_64-apple-darwin",
    packageName: `${npmScope}/upkit-darwin-x64`,
    os: "darwin",
    cpu: "x64",
    binaryFileName: "upkit",
  },
  {
    target: "aarch64-apple-darwin",
    packageName: `${npmScope}/upkit-darwin-arm64`,
    os: "darwin",
    cpu: "arm64",
    binaryFileName: "upkit",
  },
  {
    target: "x86_64-pc-windows-msvc",
    packageName: `${npmScope}/upkit-win32-x64`,
    os: "win32",
    cpu: "x64",
    binaryFileName: "upkit.exe",
  },
  {
    target: "aarch64-pc-windows-msvc",
    packageName: `${npmScope}/upkit-win32-arm64`,
    os: "win32",
    cpu: "arm64",
    binaryFileName: "upkit.exe",
  },
];

export function packageSlug(packageName) {
  return packageName.replace(/^@[^/]+\//, "");
}

export async function readCargoVersion(root = repoRoot) {
  const cargoToml = await fs.readFile(path.join(root, "Cargo.toml"), "utf8");
  return parseCargoVersion(cargoToml);
}

export function parseCargoVersion(contents) {
  let inPackageSection = false;

  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      inPackageSection = line === "[package]";
      continue;
    }
    if (!inPackageSection) {
      continue;
    }

    const versionMatch = line.match(/^version\s*=\s*"([^"]+)"\s*$/);
    if (versionMatch) {
      const [, version] = versionMatch;
      if (!packageVersionPattern.test(version)) {
        throw new Error(`invalid Cargo package version: ${version}`);
      }
      return version;
    }
  }

  throw new Error("failed to find [package].version in Cargo.toml");
}

export function mainPackageManifest(version) {
  const optionalDependencies = Object.fromEntries(
    platformPackages.map((spec) => [spec.packageName, version]),
  );

  return {
    name: mainPackageName,
    version,
    description:
      "One CLI to check and update Go, Rust, Node, Python, Flutter, and Zig toolchains",
    license: "MIT OR Apache-2.0",
    bin: {
      upkit: "./upkit",
    },
    files: ["upkit"],
    optionalDependencies,
    engines: {
      node: ">=18",
    },
    publishConfig: {
      access: "public",
    },
    repository: {
      type: "git",
      url: "git+https://github.com/christiandoxa/upkit.git",
      directory: "npm/upkit",
    },
  };
}

export function platformPackageManifest(spec, version) {
  return {
    name: spec.packageName,
    version,
    description: `Native upkit binary for ${spec.target}`,
    license: "MIT OR Apache-2.0",
    os: [spec.os],
    cpu: [spec.cpu],
    files: ["vendor"],
    engines: {
      node: ">=18",
    },
    publishConfig: {
      access: "public",
    },
    repository: {
      type: "git",
      url: "git+https://github.com/christiandoxa/upkit.git",
      directory: `npm/platforms/${packageSlug(spec.packageName)}`,
    },
  };
}

export async function ensureDir(dirPath) {
  await fs.mkdir(dirPath, { recursive: true });
}

export async function copyFile(sourcePath, destinationPath) {
  await ensureDir(path.dirname(destinationPath));
  await fs.copyFile(sourcePath, destinationPath);
}

export async function copyRepoFile(relativePath, destinationPath) {
  await copyFile(path.join(repoRoot, relativePath), destinationPath);
}

export async function writeJsonFile(filePath, value) {
  await ensureDir(path.dirname(filePath));
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

export async function readJsonFile(filePath) {
  return JSON.parse(await fs.readFile(filePath, "utf8"));
}

export async function pathExists(candidatePath) {
  try {
    await fs.access(candidatePath);
    return true;
  } catch {
    return false;
  }
}

export function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\"'\"'`)}'`;
}
