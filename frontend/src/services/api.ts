import { Investigation, HealthResponse } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

export async function downloadReportPdf(investigation: Investigation): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/investigations/report/export/pdf`, {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify(investigation)});
  if(!response.ok) throw new Error(`PDF export failed (${response.status})`);
  const url=URL.createObjectURL(await response.blob());
  const link=document.createElement('a');link.href=url;link.download='SecureMailScope_Forensic_Report.pdf';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}

export async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(`Health check failed with status: ${response.status}`);
  }
  return response.json();
}

export async function fetchDemoInvestigation(): Promise<Investigation> {
  const response = await fetch(`${API_BASE_URL}/investigations/demo`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch demo investigation: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

export async function analyzeCapture(file: File): Promise<Investigation> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE_URL}/investigations/analyze`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    let errorDetail = `Analysis failed with status ${response.status}`;
    try {
      const errJson = await response.clone().json();
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      // Non-json response fallback
      const text = await response.text();
      if (text) errorDetail = text;
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export async function fetchHardeningPolicies(): Promise<import('../types').HardeningPolicy[]> {
  const response = await fetch(`${API_BASE_URL}/investigations/policies`, {
    headers: {
      'Accept': 'application/json',
    },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch policies: ${response.status}`);
  }
  return response.json();
}

export async function runPolicySimulation(
  investigation: Investigation,
  policyIds: string[]
): Promise<import('../types').SimulationResult> {
  const response = await fetch(`${API_BASE_URL}/investigations/simulate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify({
      investigation,
      policy_ids: policyIds,
    }),
  });

  if (!response.ok) {
    let errorDetail = `Simulation failed with status ${response.status}`;
    try {
      const errJson = await response.clone().json();
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      const text = await response.text();
      if (text) errorDetail = text;
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export async function fetchClientDiscovery(
  investigation?: Investigation
): Promise<import('../types').ClientDiscoveryResult> {
  const url = investigation ? `${API_BASE_URL}/investigations/discovery` : `${API_BASE_URL}/investigations/demo/discovery`;
  const options: RequestInit = investigation
    ? {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(investigation),
      }
    : {
        headers: {
          'Accept': 'application/json',
        },
      };

  const response = await fetch(url, options);
  if (!response.ok) {
    let errorDetail = `Discovery failed with status ${response.status}`;
    try {
      const errJson = await response.clone().json();
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      const text = await response.text();
      if (text) errorDetail = text;
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export async function fetchInvestigationReport(
  investigation?: Investigation
): Promise<import('../types').InvestigationReport> {
  const url = investigation ? `${API_BASE_URL}/investigations/report` : `${API_BASE_URL}/investigations/demo/report`;
  const options: RequestInit = investigation
    ? {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(investigation),
      }
    : {
        headers: {
          'Accept': 'application/json',
        },
      };

  const response = await fetch(url, options);
  if (!response.ok) {
    let errorDetail = `Report generation failed with status ${response.status}`;
    try {
      const errJson = await response.clone().json();
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      const text = await response.text();
      if (text) errorDetail = text;
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export async function verifyReportIntegrity(
  report: import('../types').InvestigationReport
): Promise<import('../types').IntegrityVerificationResult> {
  const response = await fetch(`${API_BASE_URL}/investigations/report/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(report),
  });

  if (!response.ok) {
    let errorDetail = `Verification failed with status ${response.status}`;
    try {
      const errJson = await response.clone().json();
      if (errJson && errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      const text = await response.text();
      if (text) errorDetail = text;
    }
    throw new Error(errorDetail);
  }

  return response.json();
}

export async function downloadReportJson(investigation?: Investigation): Promise<void> {
  const url = investigation ? `${API_BASE_URL}/investigations/report/export/json` : `${API_BASE_URL}/investigations/demo/export/json`;
  const options: RequestInit = investigation
    ? {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(investigation),
      }
    : {
        method: 'GET',
      };

  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`Export JSON failed with status ${response.status}`);
  }

  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = `SecureMailScope_Report_${investigation?.sha256_short || 'export'}.json`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(downloadUrl);
  document.body.removeChild(a);
}

export async function downloadReportHtml(investigation?: Investigation): Promise<void> {
  const url = investigation ? `${API_BASE_URL}/investigations/report/export/html` : `${API_BASE_URL}/investigations/demo/report/export/html`;
  const options: RequestInit = investigation
    ? {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(investigation),
      }
    : {
        method: 'GET',
      };

  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`Export HTML failed with status ${response.status}`);
  }

  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = `SecureMailScope_Report_${investigation?.sha256_short || 'export'}.html`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(downloadUrl);
  document.body.removeChild(a);
}


