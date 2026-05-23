const fs = require('fs');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');

async function getBestModel(apiKey) {
  const defaultModel = 'gemini-1.5-flash';
  try {
    console.log('Querying available models from Google AI API...');
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`);
    if (!response.ok) {
      console.warn(`ListModels API request failed with status ${response.status}. Using default model ${defaultModel}.`);
      return defaultModel;
    }
    const data = await response.json();
    if (!data || !Array.isArray(data.models)) {
      console.warn(`Invalid response format from ListModels. Using default model ${defaultModel}.`);
      return defaultModel;
    }

    const availableModels = data.models
      .filter(m => m.supportedGenerationMethods && m.supportedGenerationMethods.includes('generateContent'))
      .map(m => m.name.replace('models/', ''));

    console.log('Available models supporting generateContent:', availableModels);

    // Order of preference
    const preferences = [
      'gemini-1.5-flash',
      'gemini-1.5-flash-latest',
      'gemini-2.5-flash',
      'gemini-2.0-flash',
      'gemini-1.5-flash-8b',
      'gemini-1.5-pro',
      'gemini-1.5-pro-latest',
      'gemini-2.5-pro'
    ];

    for (const pref of preferences) {
      if (availableModels.includes(pref)) {
        console.log(`Selected model based on preference: ${pref}`);
        return pref;
      }
    }

    // Fallback to the first available model if none of preferences match
    if (availableModels.length > 0) {
      console.log(`No preferred models found. Selecting first available: ${availableModels[0]}`);
      return availableModels[0];
    }
  } catch (err) {
    console.warn(`Error resolving available models:`, err.message);
  }
  console.log(`Using default model: ${defaultModel}`);
  return defaultModel;
}

async function fetchCisaKev() {
  console.log('Fetching CISA KEV catalog...');
  const kevSet = new Set();
  try {
    const res = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    if (res.ok) {
      const data = await res.json();
      if (data && data.vulnerabilities) {
        data.vulnerabilities.forEach(v => kevSet.add(v.cveID));
      }
    }
  } catch (err) {
    console.warn('Failed to fetch CISA KEV:', err.message);
  }
  return kevSet;
}

async function fetchEpssScores(cves) {
  if (!cves || cves.length === 0) return {};
  console.log(`Fetching EPSS scores for ${cves.length} CVEs...`);
  const epssMap = {};

  const chunkSize = 50;
  for (let i = 0; i < cves.length; i += chunkSize) {
    const chunk = cves.slice(i, i + chunkSize);
    const cveString = chunk.join(',');
    try {
      const res = await fetch(`https://api.first.org/data/v1/epss?cve=${cveString}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.data) {
          data.data.forEach(item => {
            epssMap[item.cve] = {
              epss: parseFloat(item.epss),
              percentile: parseFloat(item.percentile)
            };
          });
        }
      }
    } catch (err) {
      console.warn('Failed to fetch EPSS scores for chunk:', err.message);
    }
  }
  return epssMap;
}

function findDependencyPaths(dependencies, targetPkg, currentPath = []) {
  if (!dependencies) return [];
  let paths = [];
  for (const [name, pkg] of Object.entries(dependencies)) {
    const newPath = [...currentPath, `${name}@${pkg.version || 'unknown'}`];
    if (name === targetPkg) {
      paths.push(newPath);
    }
    if (pkg.dependencies) {
      paths.push(...findDependencyPaths(pkg.dependencies, targetPkg, newPath));
    }
  }
  return paths;
}

function formatDependencyChain(pathArray) {
  if (!pathArray || pathArray.length === 0) return 'Not found in dependency graph';
  if (pathArray.length === 1) return pathArray[0];
  let res = pathArray[0] + '\n';
  for (let i = 1; i < pathArray.length; i++) {
    const isLast = i === pathArray.length - 1;
    const prefix = '  '.repeat(i - 1) + (isLast ? '└── ' : '├── ');
    res += prefix + pathArray[i] + (isLast ? '' : '\n');
  }
  return res;
}

async function main() {
  const sbomPath = process.argv[2];
  const trivyPath = process.argv[3];
  const graphPath = process.argv[4];
  const reportPath = 'remediation-report.json';

  console.log(`Analyzing SBOM: ${sbomPath}`);
  console.log(`Analyzing Trivy: ${trivyPath}`);
  console.log(`Analyzing Dependency Graph: ${graphPath || 'None'}`);

  // Default empty report
  const defaultReport = { patches: [] };

  if (!sbomPath || !trivyPath) {
    console.error('Missing arguments. Usage: node gemini-analysis.js <sbom-file> <trivy-file> [graph-file]');
    fs.writeFileSync(reportPath, JSON.stringify(defaultReport, null, 2));
    process.exit(0);
  }

  // Get component name from SBOM filename (e.g., "backend-sbom.json" -> "backend")
  const component = path.basename(sbomPath).split('-')[0];
  console.log(`Target component: ${component}`);

  let packageJson = {};
  try {
    const packageJsonPath = path.join(component, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    }
  } catch (err) {
    console.warn(`Could not read package.json for component ${component}:`, err.message);
  }

  let trivyData = {};
  try {
    if (fs.existsSync(trivyPath)) {
      trivyData = JSON.parse(fs.readFileSync(trivyPath, 'utf8'));
    }
  } catch (err) {
    console.error(`Could not read Trivy results:`, err.message);
    fs.writeFileSync(reportPath, JSON.stringify(defaultReport, null, 2));
    process.exit(0);
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    console.warn('GEMINI_API_KEY is not set. Skipping AI analysis and generating empty report.');
    fs.writeFileSync(reportPath, JSON.stringify(defaultReport, null, 2));
    process.exit(0);
  }

  // Extract vulnerable packages and their CVEs
  const vulnerablePackagesMap = new Map();
  const cveSet = new Set();

  if (trivyData.Results) {
    for (const result of trivyData.Results) {
      if (result.Vulnerabilities) {
        for (const vuln of result.Vulnerabilities) {
          const pkgName = vuln.PkgName;
          const cveId = vuln.VulnerabilityID;

          if (cveId) cveSet.add(cveId);

          if (!vulnerablePackagesMap.has(pkgName)) {
            let depType = 'transitive';
            if (packageJson.dependencies && packageJson.dependencies[pkgName]) {
              depType = 'dependencies';
            } else if (packageJson.devDependencies && packageJson.devDependencies[pkgName]) {
              depType = 'devDependencies';
            }

            vulnerablePackagesMap.set(pkgName, {
              name: pkgName,
              installedVersion: vuln.InstalledVersion,
              fixedVersions: new Set(),
              type: depType,
              vulnerabilities: []
            });
          }

          const pkgData = vulnerablePackagesMap.get(pkgName);
          if (vuln.FixedVersion) pkgData.fixedVersions.add(vuln.FixedVersion);

          pkgData.vulnerabilities.push({
            id: cveId,
            severity: vuln.Severity
          });
        }
      }
    }
  }

  if (vulnerablePackagesMap.size === 0) {
    console.log('No vulnerable packages found. Generating empty remediation report.');
    fs.writeFileSync(reportPath, JSON.stringify(defaultReport, null, 2));
    process.exit(0);
  }

  // Load Dependency Graph
  let graphData = null;
  try {
    if (graphPath && fs.existsSync(graphPath)) {
      graphData = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
      console.log('Successfully loaded dependency graph.');
    }
  } catch (err) {
    console.warn(`Could not read dependency graph:`, err.message);
  }

  // Fetch Threat Intel Enrichments
  const kevSet = await fetchCisaKev();
  const epssMap = await fetchEpssScores(Array.from(cveSet));

  // Build final array with enrichment
  const vulnerablePackages = Array.from(vulnerablePackagesMap.values()).map(pkg => {
    pkg.vulnerabilities = pkg.vulnerabilities.map(v => {
      const epss = epssMap[v.id] || { epss: 0, percentile: 0 };
      return {
        ...v,
        isKnownExploited: kevSet.has(v.id),
        epssScore: epss.epss,
        epssPercentile: epss.percentile
      };
    });
    pkg.fixedVersions = Array.from(pkg.fixedVersions);
    
    // Attach Dependency Chain
    if (graphData && graphData.dependencies) {
      const paths = findDependencyPaths(graphData.dependencies, pkg.name);
      if (paths.length > 0) {
        paths.sort((a, b) => a.length - b.length);
        pkg.dependencyChain = formatDependencyChain(paths[0]);
      } else {
        pkg.dependencyChain = 'Not found in dependency graph';
      }
    }

    return pkg;
  });

  console.log(`Found ${vulnerablePackages.length} vulnerable packages to analyze.`);

  // Resolve best model dynamically
  const resolvedModel = await getBestModel(apiKey);
  console.log(`Resolved target model: ${resolvedModel}`);

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({
      model: resolvedModel,
      generationConfig: {
        responseMimeType: 'application/json',
      },
    });

    const prompt = `
You are a senior DevSecOps engineer.
Below is the list of vulnerable packages detected in the "${component}" component, enriched with EPSS (Exploit Prediction Scoring System) and CISA KEV (Known Exploited Vulnerabilities) data:

${JSON.stringify(vulnerablePackages, null, 2)}

Task:
Analyze the vulnerabilities and formulate a safe remediation plan. Prioritize fixes for packages with Known Exploited Vulnerabilities (isKnownExploited: true) or high EPSS scores.

Decision Tree for Remediation:
1. Direct dependency (type: "dependencies" or "devDependencies"):
   - Recommend upgrading it directly to a fixed version (or a safe compatible version).

2. Transitive dependency (type: "transitive"):
   - Find the direct parent dependency that brings in this transitive package.
   - Check if upgrading the direct parent dependency resolves the CVE.
   - If YES: Recommend upgrading the parent dependency.
   - If NO (or parent upgrade is not viable): Recommend using npm overrides. Specify the patch with "type": "overrides".

Prefer upgrading direct parent dependencies before recommending npm overrides for transitive packages.

Response Format:
Return a JSON object with a single top-level key "patches" which contains an array of objects.
Each patch object must have:
- "name": (string) the name of the npm package to upgrade or override.
- "version": (string) the recommended version string (e.g. "^4.21.2").
- "type": (string) "dependencies", "devDependencies", or "overrides".
- "confidence": (number) a confidence score between 0.0 and 1.0 representing how safe and effective the upgrade is.
- "risk": (string) "low", "medium", or "high" describing the residual risk.
- "reason": (string) explanation of why this upgrade is proposed, referencing risk (EPSS/KEV) and dependency resolution.

Example:
{
  "patches": [
    {
      "name": "express",
      "version": "^4.21.2",
      "type": "dependencies",
      "confidence": 0.93,
      "risk": "low",
      "reason": "Upgrading Express resolves the vulnerable transitive dependency path-to-regexp (high EPSS) and avoids direct override complexity."
    }
  ]
}
`;

    const response = await model.generateContent(prompt);
    const resultText = response.response.text();
    console.log('Gemini raw response:', resultText);

    // Parse response
    const parsed = JSON.parse(resultText);
    if (parsed && Array.isArray(parsed.patches)) {
      console.log(`Successfully generated remediation plan with ${parsed.patches.length} patches.`);
      fs.writeFileSync(reportPath, JSON.stringify(parsed, null, 2));
    } else {
      console.warn('Gemini response format is invalid. Falling back to default report.');
      fs.writeFileSync(reportPath, JSON.stringify(defaultReport, null, 2));
    }
  } catch (error) {
    console.error('Failed to run Gemini analysis:', error);
    fs.writeFileSync(reportPath, JSON.stringify(defaultReport, null, 2));
  }
}

main().catch(err => {
  console.error('Fatal error in gemini-analysis:', err);
  fs.writeFileSync('remediation-report.json', JSON.stringify({ patches: [] }, null, 2));
  process.exit(0);
});
