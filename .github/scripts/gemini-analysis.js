const fs = require('fs');
const path = require('path');
const { GoogleGenerativeAI } = require('@google/generative-ai');

async function main() {
  const sbomPath = process.argv[2];
  const trivyPath = process.argv[3];
  const reportPath = 'remediation-report.json';

  console.log(`Analyzing SBOM: ${sbomPath}`);
  console.log(`Analyzing Trivy: ${trivyPath}`);

  // Default empty report
  const defaultReport = { patches: [] };

  if (!sbomPath || !trivyPath) {
    console.error('Missing arguments. Usage: node gemini-analysis.js <sbom-file> <trivy-file>');
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

  // Extract only the vulnerable packages to send to Gemini
  const vulnerablePackages = [];
  const seenPackages = new Set();

  if (trivyData.Results) {
    for (const result of trivyData.Results) {
      if (result.Vulnerabilities) {
        for (const vuln of result.Vulnerabilities) {
          const pkgName = vuln.PkgName;
          
          if (!seenPackages.has(pkgName)) {
            seenPackages.add(pkgName);
            
            // Determine if direct dependency and its type
            let depType = 'transitive';
            if (packageJson.dependencies && packageJson.dependencies[pkgName]) {
              depType = 'dependencies';
            } else if (packageJson.devDependencies && packageJson.devDependencies[pkgName]) {
              depType = 'devDependencies';
            }
            
            vulnerablePackages.push({
              name: pkgName,
              installedVersion: vuln.InstalledVersion,
              fixedVersion: vuln.FixedVersion || 'None',
              severity: vuln.Severity,
              type: depType,
              vulnerabilityId: vuln.VulnerabilityID
            });
          }
        }
      }
    }
  }

  if (vulnerablePackages.length === 0) {
    console.log('No vulnerable packages found. Generating empty remediation report.');
    fs.writeFileSync(reportPath, JSON.stringify(defaultReport, null, 2));
    process.exit(0);
  }

  console.log(`Found ${vulnerablePackages.length} vulnerable packages to analyze.`);

  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    const model = genAI.getGenerativeModel({
      model: 'gemini-1.5-flash',
      generationConfig: {
        responseMimeType: 'application/json',
      },
    });

    const prompt = `
You are a senior DevSecOps engineer.
Below is the list of vulnerable packages detected in the "${component}" component:

${JSON.stringify(vulnerablePackages, null, 2)}

Task:
1. For each package, if a "fixedVersion" is available, recommend upgrading it to the fixed version (or a safe compatible version solving the vulnerability).
2. If the package is a 'transitive' dependency, recommend upgrading the direct dependency that uses it, or specify it as a patch if npm can override it.
3. Output the remediation patches.

Response Format:
Return a JSON object with a single top-level key "patches" which contains an array of objects.
Each patch object must have:
- "name": (string) the name of the npm package to upgrade.
- "version": (string) the recommended version string (e.g. "^4.21.1").
- "type": (string) either "dependencies" or "devDependencies" based on where the package is located.
- "reason": (string) a short explanation of why this upgrade is proposed.

Example:
{
  "patches": [
    {
      "name": "express",
      "version": "^4.21.1",
      "type": "dependencies",
      "reason": "Resolves CVE-2024-XXXX by upgrading to fixed version."
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
