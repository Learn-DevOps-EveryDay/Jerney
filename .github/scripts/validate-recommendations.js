const fs = require('fs');

async function validateNpmVersion(pkg, version) {
  try {
    const res = await fetch(`https://registry.npmjs.org/${pkg}`);
    if (!res.ok) return { valid: false, fallback: null };
    const data = await res.json();
    const versions = Object.keys(data.versions || {});
    const cleanVersion = version.replace(/^[^\d]+/, '');

    if (versions.includes(cleanVersion)) {
      return { valid: true, fallback: null };
    }
    
    if (data['dist-tags'] && data['dist-tags'].latest) {
      return { valid: false, fallback: data['dist-tags'].latest };
    }
    return { valid: false, fallback: null };
  } catch (err) {
    return { valid: false, fallback: null };
  }
}

async function validatePypiVersion(pkg, version) {
  try {
    const res = await fetch(`https://pypi.org/pypi/${pkg}/json`);
    if (!res.ok) return { valid: false, fallback: null };
    const data = await res.json();
    const releases = Object.keys(data.releases || {});
    const cleanVersion = version.replace(/^[^\d]+/, '');

    if (releases.includes(cleanVersion)) {
      return { valid: true, fallback: null };
    }
    
    if (data.info && data.info.version) {
      return { valid: false, fallback: data.info.version };
    }
    return { valid: false, fallback: null };
  } catch (err) {
    return { valid: false, fallback: null };
  }
}

async function validatePatch(patch) {
  if (!patch.package || !patch.recommendedVersion) {
    patch.registryConfirmed = false;
    patch.reason = (patch.reason || '') + ' [Validation Failed: Missing package or version.]';
    return patch;
  }

  const cleanVersion = patch.recommendedVersion.replace(/^[^\d]+/, '');
  let valRes = { valid: false, fallback: null };

  if (patch.ecosystem === 'pypi') {
    valRes = await validatePypiVersion(patch.package, patch.recommendedVersion);
  } else {
    // Default to npm
    valRes = await validateNpmVersion(patch.package, patch.recommendedVersion);
  }

  if (valRes.valid) {
    patch.registryConfirmed = true;
    patch.recommendedVersion = cleanVersion; // Normalize it
  } else if (valRes.fallback) {
    patch.registryConfirmed = true;
    patch.recommendedVersion = valRes.fallback;
    patch.reason = (patch.reason || '') + ` [Validation Adjusted: Replaced non-existent version with latest stable ${valRes.fallback}]`;
  } else {
    patch.registryConfirmed = false;
    patch.reason = (patch.reason || '') + ` [Validation Failed: Version does not exist in registry.]`;
  }

  return patch;
}

async function main() {
  const planPath = process.argv[2] || 'plan.json';
  const outputPath = process.argv[3] || 'validated-plan.json';

  console.log(`Validating recommendations from ${planPath}...`);

  let plan = { recommendations: [] };
  try {
    if (fs.existsSync(planPath)) {
      plan = JSON.parse(fs.readFileSync(planPath, 'utf8'));
    }
  } catch (err) {
    console.error('Failed to read plan:', err.message);
    process.exit(1);
  }

  const validated = [];
  if (plan.recommendations && Array.isArray(plan.recommendations)) {
    for (const rec of plan.recommendations) {
      console.log(`Validating ${rec.ecosystem} package ${rec.package}@${rec.recommendedVersion}...`);
      const validatedRec = await validatePatch(rec);
      validated.push(validatedRec);
      console.log(` -> Confirmed: ${validatedRec.registryConfirmed}`);
    }
  }

  plan.recommendations = validated;

  fs.writeFileSync(outputPath, JSON.stringify(plan, null, 2));
  console.log(`Validated plan saved to ${outputPath}`);
}

main().catch(err => {
  console.error('Fatal error during validation:', err);
  process.exit(1);
});
