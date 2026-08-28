import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requiredFiles = [
  'index.html',
  '_redirects',
  'assets/site.css',
  'assets/continents.geojson',
  'assets/earth_land_points.json',
  'assets/earth_surface.png',
  'assets/earth_bump.png',
  'assets/earth_clouds.png',
  'assets/earth_continents.png'
];

const missing = requiredFiles.filter(relativePath => {
  const absolutePath = path.join(root, relativePath);
  return !fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile() || fs.statSync(absolutePath).size === 0;
});

const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const localReferences = [
  ...[...html.matchAll(/(?:href|src)=["']([^"'#][^"']*)["']/g)].map(match => match[1]),
  ...[...html.matchAll(/fetch\(["']([^"']+)["']/g)].map(match => match[1])
].filter(reference => !/^(?:https?:|data:|mailto:|javascript:)/i.test(reference));

for (const reference of localReferences) {
  const relativePath = reference.split('?')[0];
  const absolutePath = path.resolve(root, relativePath);
  if (!absolutePath.startsWith(root + path.sep) || !fs.existsSync(absolutePath)) {
    missing.push(relativePath);
  }
}

const serverCheck = spawnSync(process.execPath, ['--check', path.join(root, 'server.mjs')], { encoding: 'utf8' });
if (serverCheck.status !== 0) {
  console.error(serverCheck.stderr || 'server.mjs syntax check failed');
  process.exitCode = 1;
}

const requiredMarkers = ['type="importmap"', 'three@0.179.1', 'WebGLRenderer', 'data-scene="11"', 'id="menuButton"', 'mobile-open', 'nav.github', 'nav.official', 'data-lang="ru"'];
for (const marker of requiredMarkers) {
  if (!html.includes(marker)) missing.push(`index.html marker: ${marker}`);
}

const removedMarkers = ['data-i18n="final.return"', 'href="#scene-1"><span data-i18n="final.return"'];
for (const marker of removedMarkers) {
  if (html.includes(marker)) missing.push(`removed UI marker still present: ${marker}`);
}

if (missing.length) {
  console.error('Static production build failed. Missing or invalid entries:');
  for (const entry of [...new Set(missing)]) console.error(`- ${entry}`);
  process.exitCode = 1;
} else if (serverCheck.status === 0) {
  console.log(`Static production build verified successfully.`);
  console.log(`Build output directory: ${root}`);
}
