const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function execCmd(cmd, cwd) {
  try {
    execSync(cmd, { cwd, stdio: 'pipe', timeout: 120000 });
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function parseSemver(version) {
  const parts = version.replace(/^[^\d]+/, '').split('.');
  return {
    major: parseInt(parts[0] || '0', 10),
    minor: parseInt(parts[1] || '0', 10),
    patch: parseInt(parts[2] || '0', 10)
  };
}

function calculatePatchDistance(current, target) {
  const c = parseSemver(current);
  const t = parseSemver(target);
  return Math.abs(t.major - c.major) * 100 + Math.abs(t.minor - c.minor) * 10 + Math.abs(t.patch - c.patch);
}

function main() {
  const args = process.argv.slice(2);
  const scenariosPath = args[0] || 'scenarios.json';
  const detPlanPath = args[1] || 'deterministic-plan.json';
  const aiPlanPath = args[2] || 'ai-plan.json';
  const outputPath = args[3] || 'experiment-results.json';

  console.log('Starting Experiment Runner...');

  let scenarios = { scenarios: [] };
  let detPlan = { recommendations: [] };
  let aiPlan = { recommendations: [] };

  try {
    scenarios = JSON.parse(fs.readFileSync(scenariosPath, 'utf8'));
    if (fs.existsSync(detPlanPath)) detPlan = JSON.parse(fs.readFileSync(detPlanPath, 'utf8'));
    if (fs.existsSync(aiPlanPath)) aiPlan = JSON.parse(fs.readFileSync(aiPlanPath, 'utf8'));
  } catch (err) {
    console.error('Failed to read input files:', err.message);
    process.exit(1);
  }

  const results = [];
  const rootDir = process.cwd();

  for (const scenario of scenarios.scenarios) {
    console.log(`\nEvaluating Scenario ${scenario.id}: ${scenario.package} in ${scenario.component}`);
    
    const detRec = detPlan.recommendations.find(r => r.scenarioId === scenario.id);
    const aiRec = aiPlan.recommendations.find(r => r.scenarioId === scenario.id);

    const scenarioResult = {
      scenarioId: scenario.id,
      component: scenario.component,
      ecosystem: scenario.ecosystem,
      package: scenario.package,
      cveId: scenario.cveId,
      severity: scenario.severity,
      conditions: {
        deterministic: { gates: {} },
        ai: { gates: {} }
      }
    };

    const conditionsToTest = [
      { name: 'deterministic', rec: detRec },
      { name: 'ai', rec: aiRec }
    ];

    for (const cond of conditionsToTest) {
      console.log(` -> Condition: ${cond.name}`);
      const resCond = scenarioResult.conditions[cond.name];

      if (!cond.rec) {
        console.log(`    No recommendation found. Skipping all gates.`);
        ['dependencyResolution', 'build', 'test', 'vulnerabilityRescan'].forEach(g => {
          resCond.gates[g] = { status: 'skip', note: 'No recommendation' };
        });
        continue;
      }

      resCond.recommendedVersion = cond.rec.recommendedVersion;
      resCond.registryConfirmed = cond.rec.registryConfirmed;
      resCond.patchDistance = calculatePatchDistance(scenario.installedVersion, cond.rec.recommendedVersion);

      if (!cond.rec.registryConfirmed) {
        console.log(`    Registry unconfirmed. Failing all gates.`);
        ['dependencyResolution', 'build', 'test', 'vulnerabilityRescan'].forEach(g => {
          resCond.gates[g] = { status: 'fail', note: 'Registry validation failed' };
        });
        continue;
      }

      // Prepare temp sandbox
      const compPath = path.join(rootDir, scenario.component);
      const tempPath = path.join(rootDir, `.temp-${scenario.id}-${cond.name}`);
      
      try {
        if (fs.existsSync(tempPath)) fs.rmSync(tempPath, { recursive: true, force: true });
        fs.cpSync(compPath, tempPath, { recursive: true });

        let depRes = 'fail';
        let depNote = '';

        // Gate 1: Dependency Resolution
        console.log('    [Gate 1] Dependency Resolution...');
        if (scenario.ecosystem === 'npm') {
          // Edit package.json natively to simulate patch
          const pkgJsonPath = path.join(tempPath, 'package.json');
          const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
          if (cond.rec.type === 'overrides') {
            pkgJson.overrides = pkgJson.overrides || {};
            pkgJson.overrides[scenario.package] = cond.rec.recommendedVersion;
          } else {
            const section = cond.rec.type || 'dependencies';
            if (!pkgJson[section]) pkgJson[section] = {};
            pkgJson[section][scenario.package] = cond.rec.recommendedVersion;
          }
          fs.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson, null, 2));

          const r = execCmd('npm install --package-lock-only --ignore-scripts', tempPath);
          if (r.success) { depRes = 'pass'; } else { depNote = 'npm install failed'; }
        } else {
          // pypi
          const reqPath = path.join(tempPath, 'requirements.txt');
          let reqs = fs.readFileSync(reqPath, 'utf8');
          // Replace package version
          const regex = new RegExp(`^${scenario.package}(==|>=|~=).*$`, 'im');
          if (regex.test(reqs)) {
            reqs = reqs.replace(regex, `${scenario.package}==${cond.rec.recommendedVersion}`);
          } else {
            reqs += `\n${scenario.package}==${cond.rec.recommendedVersion}`;
          }
          fs.writeFileSync(reqPath, reqs);
          
          const r = execCmd('pip install --dry-run -r requirements.txt', tempPath);
          if (r.success) { depRes = 'pass'; } else { depNote = 'pip dry-run failed'; }
        }
        resCond.gates.dependencyResolution = { status: depRes, note: depNote };

        // If Gate 1 fails, cascade fails
        if (depRes === 'fail') {
          console.log(`    Gate 1 failed. Skipping remainder.`);
          ['build', 'test', 'vulnerabilityRescan'].forEach(g => {
            resCond.gates[g] = { status: 'fail', note: 'Cascading failure from Gate 1' };
          });
          continue;
        }

        // Gate 2: Build
        console.log('    [Gate 2] Build...');
        let buildRes = 'skip';
        let buildNote = 'No build step required';
        if (scenario.ecosystem === 'npm') {
          const pkgJson = JSON.parse(fs.readFileSync(path.join(tempPath, 'package.json'), 'utf8'));
          if (pkgJson.scripts && pkgJson.scripts.build) {
             const r = execCmd('npm run build', tempPath);
             buildRes = r.success ? 'pass' : 'fail';
             buildNote = r.success ? '' : 'npm run build failed';
          }
        }
        resCond.gates.build = { status: buildRes, note: buildNote };
        if (buildRes === 'fail') {
          console.log(`    Gate 2 failed. Skipping remainder.`);
          ['test', 'vulnerabilityRescan'].forEach(g => {
            resCond.gates[g] = { status: 'fail', note: 'Cascading failure from Gate 2' };
          });
          continue;
        }

        // Gate 3: Test
        console.log('    [Gate 3] Test...');
        let testRes = 'skip';
        let testNote = 'No tests found';
        if (scenario.ecosystem === 'npm') {
          const pkgJson = JSON.parse(fs.readFileSync(path.join(tempPath, 'package.json'), 'utf8'));
          if (pkgJson.scripts && pkgJson.scripts.test && !pkgJson.scripts.test.includes('no test specified')) {
             const r = execCmd('npm test', tempPath);
             testRes = r.success ? 'pass' : 'fail';
             testNote = r.success ? '' : 'npm test failed';
          }
        } else {
          if (fs.existsSync(path.join(tempPath, 'tests'))) {
             const r = execCmd('pytest tests/', tempPath);
             testRes = r.success ? 'pass' : 'fail';
             testNote = r.success ? '' : 'pytest failed';
          }
        }
        resCond.gates.test = { status: testRes, note: testNote };
        if (testRes === 'fail') {
          console.log(`    Gate 3 failed. Skipping remainder.`);
          resCond.gates.vulnerabilityRescan = { status: 'fail', note: 'Cascading failure from Gate 3' };
          continue;
        }

        // Gate 4: Rescan
        console.log('    [Gate 4] Vulnerability Rescan...');
        let scanRes = 'fail';
        let scanNote = 'CVE still present';
        try {
          const scanOut = execSync(`grype dir:. -o json -q`, { cwd: tempPath, encoding: 'utf8' });
          const scanJson = JSON.parse(scanOut);
          const stillExists = scanJson.matches && scanJson.matches.some(m => m.vulnerability.id === scenario.cveId);
          if (!stillExists) {
            scanRes = 'pass';
            scanNote = 'CVE successfully resolved';
          }
        } catch (e) {
          scanNote = 'Grype scan failed to execute';
        }
        resCond.gates.vulnerabilityRescan = { status: scanRes, note: scanNote };

      } finally {
        // Cleanup temp dir
        if (fs.existsSync(tempPath)) fs.rmSync(tempPath, { recursive: true, force: true });
      }
    }

    results.push(scenarioResult);
  }

  const finalOutput = {
    experimentDate: new Date().toISOString(),
    scenarioCount: results.length,
    results
  };

  fs.writeFileSync(outputPath, JSON.stringify(finalOutput, null, 2));
  console.log(`\nExperiment completed. Results saved to ${outputPath}`);
}

main();
