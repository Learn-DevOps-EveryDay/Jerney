const fs = require('fs');

async function validatePatch(patch) {
  if (!patch.name || !patch.version) {
    return {
      ...patch,
      valid: false,
      reason: `${patch.reason || ''} [Validation Failed: Missing name or version.]`
    };
  }

  try {
    const res = await fetch(`https://registry.npmjs.org/${patch.name}`);
    if (!res.ok) {
      return {
        ...patch,
        valid: false,
        reason: `${patch.reason || ''} [Validation Failed: Package '${patch.name}' not found or registry error.]`
      };
    }
    const data = await res.json();
    const versions = Object.keys(data.versions || {});

    // Clean version string: remove ^, ~, >=, <=, etc.
    const cleanVersion = patch.version.replace(/^[^\d]+/, '');

    if (versions.includes(cleanVersion)) {
      return {
        ...patch,
        valid: true
      };
    }

    // Attempt fallback to latest dist-tag if explicit version fails
    if (data['dist-tags'] && data['dist-tags'].latest) {
      const latest = data['dist-tags'].latest;
      return {
        ...patch,
        version: `^${latest}`,
        valid: true,
        reason: `${patch.reason || ''} [Validation Adjusted: Replaced non-existent version ${patch.version} with latest stable ${latest}]`
      };
    }

    return {
      ...patch,
      valid: false,
      reason: `${patch.reason || ''} [Validation Failed: Version ${cleanVersion} does not exist in npm registry.]`
    };
  } catch (err) {
    return {
      ...patch,
      valid: false,
      reason: `${patch.reason || ''} [Validation Failed: Registry fetch error - ${err.message}]`
    };
  }
}

async function main() {
  const reportPath = process.argv[2] || 'remediation-report.json';
  const outputPath = process.argv[3] || 'validated-remediation-report.json';

  console.log(`Validating recommendations from ${reportPath}...`);

  let report = { patches: [] };
  try {
    if (fs.existsSync(reportPath)) {
      report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    }
  } catch (err) {
    console.error('Failed to read remediation report:', err.message);
    fs.writeFileSync(outputPath, JSON.stringify({ patches: [] }, null, 2));
    process.exit(1);
  }

  const validated = [];
  if (report.patches && Array.isArray(report.patches)) {
    for (const patch of report.patches) {
      console.log(`Validating patch for ${patch.name}@${patch.version}...`);
      const validatedPatch = await validatePatch(patch);
      validated.push(validatedPatch);
      console.log(` -> Valid: ${validatedPatch.valid}`);
    }
  }

  // Wrap the output back into the expected { patches: [] } structure
  fs.writeFileSync(outputPath, JSON.stringify({ patches: validated }, null, 2));
  console.log(`Validated report saved to ${outputPath}`);
}

main().catch(err => {
  console.error('Fatal error during validation:', err);
  fs.writeFileSync(process.argv[3] || 'validated-remediation-report.json', JSON.stringify({ patches: [] }, null, 2));
  process.exit(1);
});
