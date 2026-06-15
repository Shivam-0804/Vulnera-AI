export const SCAN_TYPES = {
  passive: {
    label: 'Passive Scan',
    description: 'Quick and non-intrusive. Analyzes traffic without attacking the target.',
    duration_hint: '~1 min',
    icon: '🔍',
  },
  normal: {
    label: 'Normal Scan',
    description: 'Balanced coverage. Crawls the site and detects service versions.',
    duration_hint: '~3–5 min',
    icon: '⚡',
  },
  deep: {
    label: 'Deep Scan',
    description: 'Thorough assessment. Active attack simulation and comprehensive port scan.',
    duration_hint: '~10–20 min',
    icon: '🎯',
  },
}

export const DEFAULT_SCAN_TYPE = 'passive'

export const LOADING_MESSAGES = {
  passive: {
    title: 'Passive scan in progress',
    description: 'Analyzing traffic with ZAP and running a fast port scan...',
    steps: ['ZAP Passive', 'Nmap Fast', 'Gemini AI'],
  },
  normal: {
    title: 'Normal scan in progress',
    description: 'Spider crawling, passive analysis, and service detection...',
    steps: ['ZAP Spider', 'Nmap -sV', 'Gemini AI'],
  },
  deep: {
    title: 'Deep scan in progress',
    description: 'Full spider crawl, active attack simulation, and comprehensive port scan...',
    steps: ['ZAP Active', 'Nmap Deep', 'Gemini AI'],
  },
}
