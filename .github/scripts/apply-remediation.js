const fs = require('fs');
const path = require('path');

function main() {
  const reportPath = process.argv[2];
  const component = process.argv[3];

  console.log(`Applying remediation report ${reportPath} to component ${component}`);

  if (!reportPath || !component) {
    console.error('Missing arguments. Usage: node apply-remediation.js <report-file> <component-dir>');
    process.exit(1);
  }

  const packageJsonPath = path.join(component, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    console.error(`package.json not found at ${packageJsonPath}`);
    process.exit(1);
  }

  let report = { patches: [] };
  try {
    report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  } catch (err) {
    console.error(`Failed to read remediation report:`, err.message);
    process.exit(1);
  }

  if (!report.patches || report.patches.length === 0) {
    console.log('No patches to apply.');
    process.exit(0);
  }

  let packageJson = {};
  try {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch (err) {
    console.error(`Failed to read package.json:`, err.message);
    process.exit(1);
  }

  let modified = false;
  for (const patch of report.patches) {
    if (patch.valid === false) {
      console.warn(`Skipping invalid patch for ${patch.name}: ${patch.reason || 'Validation failed.'}`);
      continue;
    }

    const { name, version, type } = patch;
    if (!name || !version) {
      console.warn('Skipping invalid patch format:', patch);
      continue;
    }

    const targetType = type || 'dependencies';
    if (!packageJson[targetType]) {
      packageJson[targetType] = {};
    }

    const oldVersion = packageJson[targetType][name];
    console.log(`Applying patch: ${name} (${oldVersion || 'none'} -> ${version}) in ${targetType}`);
    packageJson[targetType][name] = version;
    modified = true;
  }

  if (modified) {
    fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n');
    console.log(`Successfully updated package.json for ${component}`);
  } else {
    console.log('No modifications were made to package.json.');
  }
}

main();
